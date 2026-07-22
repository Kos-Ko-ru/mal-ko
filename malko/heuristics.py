"""Heuristic static-analysis engine (pure stdlib).

Layers on top of the hash blocklist: scores files with lightweight
static rules — PE header/import analysis (manual struct parsing),
per-section Shannon entropy, double extensions, risky locations, script
content patterns, Office macro indicators and the EICAR test string.

Verdicts:
  CLEAN        score < 50
  SUSPICIOUS   50 <= score < 90   -> loud warning, NOT quarantined
  SUSPICIOUS+  score >= 90        -> still just a heuristic verdict
  EICAR-TEST   EICAR string found -> treated as confirmed (quarantined)

Heuristics produce false positives by nature — nothing here is proof of
malice. Rules are data-driven (RULES list); each rule is a function
taking a context dict and returning hits {"id", "points", "description"}.
"""

import math
import os
import re
import struct
from pathlib import Path

SUSPICIOUS_THRESHOLD = 50
MALICIOUS_THRESHOLD = 90
HIGH_ENTROPY = 7.2
MAX_CONTENT_READ = 512 * 1024
MAX_PE_READ = 200 * 1024 * 1024

EXEC_EXTS = {"exe", "dll", "scr", "com", "pif"}
SCRIPT_EXTS = {"bat", "cmd", "ps1", "vbs", "js"}
OFFICE_EXTS = {"doc", "docm", "xls", "xlsm"}
RELEVANT_EXTS = EXEC_EXTS | SCRIPT_EXTS | OFFICE_EXTS | {"jar"}
DOC_LIKE_EXTS = {
    "jpg", "jpeg", "png", "gif", "bmp", "pdf", "doc", "docx", "xls",
    "xlsx", "ppt", "txt", "zip", "rar", "7z", "mp3", "mp4",
}
RISKY_DIR_NAMES = {"temp", "tmp", "downloads"}

EICAR_STRING = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

# Image section characteristics flags.
_SCN_MEM_EXECUTE = 0x20000000
_SCN_MEM_WRITE = 0x80000000


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def shannon_entropy(data):
    """Shannon entropy (bits/byte) of a bytes object; 0.0 for empty input."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def extension_of(path):
    suffix = Path(path).suffix.lower()
    return suffix[1:] if suffix.startswith(".") else suffix


def is_risky_location(path):
    """True for temp dirs / Downloads and AppData\\Local\\Temp."""
    p = str(path).lower().replace("/", "\\")
    if "appdata\\local\\temp" in p:
        return True
    parts = {part for part in re.split(r"[\\/]", p) if part}
    return bool(parts & RISKY_DIR_NAMES)


def should_analyze(path):
    """Which files are worth heuristic analysis."""
    ext = extension_of(path)
    if ext in RELEVANT_EXTS:
        return True
    return ext == "" and is_risky_location(path)


def _read_head(path, limit=MAX_CONTENT_READ):
    try:
        with open(path, "rb") as fh:
            return fh.read(limit)
    except OSError:
        return b""


# ---------------------------------------------------------------------------
# PE parsing (DOS header -> PE offset -> COFF -> optional header -> sections,
# import directory). Fully defensive: malformed input returns None.
# ---------------------------------------------------------------------------

def _read_c_string(data, offset, limit=256):
    if offset is None or offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset, offset + limit)
    if end == -1:
        end = min(len(data), offset + limit)
    return data[offset:end].decode("ascii", errors="replace")


def parse_pe(path):
    """Parse a PE file. Returns a dict or None when not a (parseable) PE.

    Keys: is_exe, entry_rva, entry_section, sections (name, entropy,
    characteristics, virtual_address, virtual_size, raw_size),
    imports ({dll_lowercase: [function names]}).
    """
    try:
        size = os.path.getsize(path)
        if size > MAX_PE_READ:
            return None
        data = Path(path).read_bytes()
        if len(data) < 0x40 or data[:2] != b"MZ":
            return None
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_off + 24 > len(data) or data[pe_off:pe_off + 4] != b"PE\x00\x00":
            return None
        coff = pe_off + 4
        num_sections = struct.unpack_from("<H", data, coff + 2)[0]
        size_opt = struct.unpack_from("<H", data, coff + 16)[0]
        characteristics = struct.unpack_from("<H", data, coff + 18)[0]
        opt = coff + 20
        if opt + size_opt > len(data) or num_sections > 96:
            return None
        magic = struct.unpack_from("<H", data, opt)[0]
        is64 = magic == 0x20B
        if magic not in (0x10B, 0x20B):
            return None
        entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
        dd_base = opt + (112 if is64 else 96)
        import_rva = 0
        if dd_base + 16 <= opt + size_opt:
            import_rva = struct.unpack_from("<I", data, dd_base + 8)[0]

        sections = []
        sec_off = opt + size_opt
        for i in range(num_sections):
            base = sec_off + i * 40
            if base + 40 > len(data):
                return None
            name = data[base:base + 8].rstrip(b"\x00").decode("ascii", "replace")
            vsize, vaddr, raw_size, raw_ptr = struct.unpack_from(
                "<IIII", data, base + 8
            )
            chars = struct.unpack_from("<I", data, base + 36)[0]
            raw = data[raw_ptr:raw_ptr + min(raw_size, max(0, len(data) - raw_ptr))]
            sections.append(
                {
                    "name": name,
                    "virtual_address": vaddr,
                    "virtual_size": vsize,
                    "raw_size": raw_size,
                    "raw_ptr": raw_ptr,
                    "characteristics": chars,
                    "entropy": shannon_entropy(raw),
                }
            )

        def rva_to_offset(rva):
            for sec in sections:
                span = max(sec["virtual_size"], sec["raw_size"])
                if sec["virtual_address"] <= rva < sec["virtual_address"] + span:
                    return sec["raw_ptr"] + (rva - sec["virtual_address"])
            return None

        imports = {}
        desc_off = rva_to_offset(import_rva) if import_rva else None
        if desc_off is not None:
            thunk_size = 8 if is64 else 4
            ordinal_flag = 0x8000000000000000 if is64 else 0x80000000
            for _ in range(4096):  # descriptor walk, hard-capped
                if desc_off + 20 > len(data):
                    break
                oft, _, _, name_rva, ft = struct.unpack_from(
                    "<IIIII", data, desc_off
                )
                if oft == 0 and name_rva == 0 and ft == 0:
                    break  # terminator descriptor
                dll = _read_c_string(data, rva_to_offset(name_rva)).lower()
                funcs = []
                thunk_off = rva_to_offset(oft or ft)
                if thunk_off is not None:
                    for _ in range(8192):  # thunk walk, hard-capped
                        if thunk_off + thunk_size > len(data):
                            break
                        fmt = "<Q" if is64 else "<I"
                        value = struct.unpack_from(fmt, data, thunk_off)[0]
                        if value == 0:
                            break
                        if not (value & ordinal_flag):
                            name_off = rva_to_offset(value & 0x7FFFFFFF)
                            if name_off is not None:
                                funcs.append(_read_c_string(data, name_off + 2))
                        thunk_off += thunk_size
                if dll:
                    imports.setdefault(dll, []).extend(funcs)
                desc_off += 20

        entry_section = None
        for sec in sections:
            span = max(sec["virtual_size"], sec["raw_size"])
            if sec["virtual_address"] <= entry_rva < sec["virtual_address"] + span:
                entry_section = sec["name"]
                break

        return {
            "is_exe": bool(characteristics & 0x0002),
            "entry_rva": entry_rva,
            "entry_section": entry_section,
            "sections": sections,
            "imports": imports,
        }
    except (OSError, struct.error, IndexError, ValueError, OverflowError):
        return None


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

def _hit(rule_id, points, description):
    return {"id": rule_id, "points": points, "description": description}


def _rule_double_extension(ctx):
    parts = ctx["path"].name.lower().split(".")
    if (
        len(parts) >= 3
        and parts[-1] in (EXEC_EXTS | SCRIPT_EXTS)
        and parts[-2] in DOC_LIKE_EXTS
    ):
        return [
            _hit(
                "double-extension",
                60,
                f"double extension '.{parts[-2]}.{parts[-1]}' "
                "masquerades as a document/media file",
            )
        ]
    return []


def _rule_risky_location(ctx):
    if ctx["ext"] in (EXEC_EXTS | SCRIPT_EXTS) or ctx["ext"] == "":
        if is_risky_location(ctx["path"]):
            return [
                _hit(
                    "risky-location",
                    30,
                    "executable/script in a temporary or download location",
                )
            ]
    return []


_SCRIPT_PATTERNS = [
    ("script-powershell-enc", ("powershell", "-enc"), 35,
     "PowerShell with -enc(odedcommand)"),
    ("script-frombase64string", ("frombase64string",), 35,
     "Base64 payload decoding (FromBase64String)"),
    ("script-invoke-expression", ("invoke-expression",), 35,
     "dynamic code execution (Invoke-Expression)"),
    ("script-certutil-decode", ("certutil", "-decode"), 35,
     "certutil used to decode a payload"),
    ("script-mshta-http", ("mshta", "http"), 35,
     "mshta fetching remote content"),
    ("script-downloadstring", ("downloadstring",), 30,
     "web download cradle (DownloadString)"),
]


def _rule_script_patterns(ctx):
    if ctx["ext"] not in SCRIPT_EXTS and not (
        ctx["ext"] == "" and is_risky_location(ctx["path"])
    ):
        return []
    try:
        text = _read_head(ctx["path"]).decode("utf-8", errors="ignore").lower()
    except OSError:
        return []
    if not text:
        return []
    hits = []
    for rule_id, needles, points, description in _SCRIPT_PATTERNS:
        if all(needle in text for needle in needles):
            hits.append(_hit(rule_id, points, description))
    return hits


def _rule_office_macro(ctx):
    ext = ctx["ext"]
    if ext not in OFFICE_EXTS:
        return []
    content = _read_head(ctx["path"])
    if not content:
        return []
    lower = content.lower()
    hits = []
    if ext in ("doc", "xls"):
        if b"autoopen" in lower or b"auto_open" in lower:
            hits.append(_hit("office-autoopen", 40,
                             "legacy Office document with AutoOpen/Auto_Open macro"))
        if b"wscript.shell" in lower:
            hits.append(_hit("office-wscript-shell", 30,
                             "Office document references WScript.Shell"))
    if ext in ("docm", "xlsm") and b"vbaproject" in lower:
        hits.append(_hit("office-vba-project", 30,
                         "macro-enabled Office file contains a VBA project"))
    return hits


def _rule_pe_indicators(ctx):
    if ctx["ext"] not in EXEC_EXTS and ctx["ext"] != "":
        return []
    pe = ctx.get("pe")
    if pe is None:
        return []  # malformed PE: skip PE rules quietly
    hits = []
    funcs = {name for names in pe["imports"].values() for name in names}

    if pe["is_exe"] and not pe["imports"]:
        hits.append(_hit("pe-no-imports", 30,
                         "executable has no import table (likely packed)"))
    if {"VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"} <= funcs:
        hits.append(_hit("pe-injection-combo", 40,
                         "process-injection import combo "
                         "(VirtualAlloc + WriteProcessMemory + CreateRemoteThread)"))
    if "URLDownloadToFile" in funcs or "URLDownloadToFileA" in funcs:
        hits.append(_hit("pe-urldownload", 25, "imports URLDownloadToFile"))
    if "WinExec" in funcs:
        hits.append(_hit("pe-winexec", 15, "imports WinExec"))
    if any(f.startswith("ShellExecute") for f in funcs):
        hits.append(_hit("pe-shellexecute", 10, "imports ShellExecute"))
    if "IsDebuggerPresent" in funcs:
        hits.append(_hit("pe-anti-debug", 15, "imports IsDebuggerPresent"))
    if "VirtualProtect" in funcs:
        hits.append(_hit("pe-virtualprotect", 10, "imports VirtualProtect"))
    if any(f.startswith("SetWindowsHookEx") for f in funcs):
        hits.append(_hit("pe-hook", 20, "imports SetWindowsHookEx (keylogger-style hook)"))
    dynamic_only = {
        "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
        "GetProcAddress", "FreeLibrary",
    }
    if funcs and funcs <= dynamic_only and len(funcs) <= 5:
        hits.append(_hit("pe-dynamic-resolution-only", 25,
                         "resolves all APIs dynamically "
                         "(LoadLibrary/GetProcAddress only)"))

    for section in pe["sections"]:
        if section["raw_size"] > 0 and section["entropy"] > HIGH_ENTROPY:
            hits.append(_hit(
                "pe-high-entropy-section", 30,
                f"section {section['name']!r} has high entropy "
                f"({section['entropy']:.2f}, likely packed)",
            ))
        flags = section["characteristics"]
        if flags & _SCN_MEM_EXECUTE and flags & _SCN_MEM_WRITE:
            hits.append(_hit(
                "pe-writable-executable-section", 25,
                f"section {section['name']!r} is both writable and executable",
            ))
    if pe["sections"] and pe["entry_section"] == pe["sections"][-1]["name"]:
        hits.append(_hit("pe-entry-in-last-section", 20,
                         "entry point is in the last section (packer trait)"))
    return hits


RULES = [
    _rule_double_extension,
    _rule_risky_location,
    _rule_script_patterns,
    _rule_office_macro,
    _rule_pe_indicators,
]


# ---------------------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------------------

def verdict_for_score(score):
    if score >= MALICIOUS_THRESHOLD:
        return "SUSPICIOUS+"
    if score >= SUSPICIOUS_THRESHOLD:
        return "SUSPICIOUS"
    return "CLEAN"


def analyze(path):
    """Run all rules against one file.

    Returns {"verdict", "score", "rules": [hits]}. EICAR short-circuits
    to verdict "EICAR-TEST". Never raises on unreadable/malformed input.
    """
    path = Path(path)
    head = _read_head(path, 4096)
    if EICAR_STRING in head:
        return {
            "verdict": "EICAR-TEST",
            "score": MALICIOUS_THRESHOLD,
            "rules": [_hit("eicar-test-file", MALICIOUS_THRESHOLD,
                           "EICAR antivirus test string detected")],
        }
    ctx = {"path": path, "ext": extension_of(path)}
    ctx["pe"] = parse_pe(path) if ctx["ext"] in EXEC_EXTS or ctx["ext"] == "" else None
    hits = []
    for rule in RULES:
        try:
            hits.extend(rule(ctx))
        except Exception:  # noqa: BLE001 - one bad rule must not kill a scan
            continue
    score = sum(hit["points"] for hit in hits)
    return {"verdict": verdict_for_score(score), "score": score, "rules": hits}
