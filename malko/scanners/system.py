"""Installed-software scanner.

Inventories installed products (Windows: registry Uninstall keys;
Linux: dpkg-query/rpm), then checks each product name against the NVD
CVE API (keyword search, polite ~1.5 s delay between requests) and the
CISA KEV catalog.
"""

import platform
import shutil
import subprocess
import sys
import time

from ..sources import kev, nvd

NVD_DELAY = 1.5  # seconds between NVD requests (no API key)


def _inventory_windows():
    """Read DisplayName/DisplayVersion from registry Uninstall keys."""
    import winreg

    products = []
    subkey_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    views = [
        (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_READ | winreg.KEY_WOW64_64KEY),
        (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_READ | winreg.KEY_WOW64_32KEY),
        (winreg.HKEY_CURRENT_USER, winreg.KEY_READ),
    ]
    seen = set()
    for hive, access in views:
        try:
            with winreg.OpenKey(hive, subkey_path, 0, access) as root:
                count = winreg.QueryInfoKey(root)[0]
                for i in range(count):
                    try:
                        with winreg.OpenKey(root, winreg.EnumKey(root, i)) as sub:
                            name, _ = winreg.QueryValueEx(sub, "DisplayName")
                            try:
                                version, _ = winreg.QueryValueEx(sub, "DisplayVersion")
                            except OSError:
                                version = ""
                    except OSError:
                        continue
                    name = str(name).strip()
                    if name and name not in seen:
                        seen.add(name)
                        products.append({"name": name, "version": str(version).strip()})
        except OSError:
            continue
    return products


def _run_lines(command):
    output = subprocess.run(
        command, capture_output=True, text=True, timeout=120, check=False
    )
    return [line for line in output.stdout.splitlines() if line.strip()]


def _inventory_linux():
    """dpkg-query first, rpm as fallback. None when neither exists."""
    if shutil.which("dpkg-query"):
        products = []
        for line in _run_lines(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"]):
            name, _, version = line.partition("\t")
            products.append({"name": name.strip(), "version": version.strip()})
        return products
    if shutil.which("rpm"):
        products = []
        for line in _run_lines(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}\n"]):
            name, _, version = line.partition("\t")
            products.append({"name": name.strip(), "version": version.strip()})
        return products
    return None


def inventory():
    """Return (products, error_message). products is a list of dicts."""
    system = platform.system()
    if system == "Windows":
        return _inventory_windows(), None
    if system == "Linux":
        products = _inventory_linux()
        if products is None:
            return [], (
                "unsupported system: neither dpkg-query nor rpm found; "
                "installed-software inventory is not available"
            )
        return products, None
    return [], f"unsupported system: {system or 'unknown'} (inventory not implemented)"


def scan(max_products=30, delay=NVD_DELAY, progress=True):
    """Inventory installed software and check it against NVD and KEV.

    Returns {"products": [...], "findings": [...], "error": str|None}.
    """
    products, error = inventory()
    findings = []
    if error:
        return {"products": products, "findings": findings, "error": error}

    kev_entries = kev.load_catalog()
    checked = products[:max_products]
    for index, product in enumerate(checked):
        name = product["name"]
        if progress:
            print(f"[{index + 1}/{len(checked)}] checking: {name}", file=sys.stderr)

        for entry in kev.match_product(kev_entries, name):
            findings.append(
                {
                    "id": entry.get("cveID", ""),
                    "severity": "CRITICAL",
                    "title": (
                        f"ACTIVELY EXPLOITED (CISA KEV): {name} matches "
                        f"{entry.get('vendorProject', '')} {entry.get('product', '')} "
                        f"- {entry.get('vulnerabilityName', '')}"
                    ),
                    "details": {
                        "product": name,
                        "version": product["version"],
                        "source": "CISA KEV",
                        "dateAdded": entry.get("dateAdded", ""),
                    },
                }
            )

        try:
            cves = nvd.keyword_search(name)
        except Exception as exc:  # noqa: BLE001 - keep scanning other products
            print(f"warning: NVD query failed for {name!r}: {exc}", file=sys.stderr)
            cves = []
        for cve in cves:
            findings.append(
                {
                    "id": cve["id"],
                    "severity": cve["severity"],
                    "title": f"{name} {product['version']}: {cve['description']}",
                    "details": {
                        "product": name,
                        "version": product["version"],
                        "source": "NVD keyword search",
                    },
                }
            )
        if index < len(checked) - 1:
            time.sleep(delay)

    note = None
    if len(products) > max_products:
        note = f"showing first {max_products} of {len(products)} products (--max-products)"
    return {"products": checked, "findings": findings, "error": error, "note": note}
