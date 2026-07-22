"""Shared HTTP helper for all threat-intel sources.

Standard library only (urllib). Every request has a timeout and one
retry (2 attempts total). Network/HTTP failures raise SourceError with
a human-readable message so the CLI can report "offline" cleanly.
"""

import json
import time
import urllib.error
import urllib.parse
import urllib.request

# Note: keep this plain. A "(+https://...)" comment suffix gets 403'd by
# the CDN in front of www.cisa.gov.
USER_AGENT = "mal-ko/0.1"
DEFAULT_TIMEOUT = 30
ATTEMPTS = 2


class SourceError(Exception):
    """Raised when a remote source cannot be reached or answers badly."""


def _build_request(url, json_body=None, form=None, headers=None):
    req_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        req_headers.update(headers)
    data = None
    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        req_headers["Content-Type"] = "application/json"
    elif form is not None:
        data = urllib.parse.urlencode(form).encode("utf-8")
        req_headers["Content-Type"] = "application/x-www-form-urlencoded"
    return urllib.request.Request(url, data=data, headers=req_headers)


def _request(url, *, json_body=None, form=None, headers=None,
             timeout=DEFAULT_TIMEOUT):
    """Fetch raw response bytes. Retries once, raises SourceError."""
    last_error = None
    for attempt in range(1, ATTEMPTS + 1):
        try:
            req = _build_request(url, json_body=json_body, form=form,
                                 headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            last_error = SourceError(f"HTTP {exc.code} from {url}")
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", exc)
            last_error = SourceError(
                f"cannot reach {url} ({reason}). Check your internet connection."
            )
        except (TimeoutError, OSError) as exc:
            last_error = SourceError(f"timeout/error talking to {url} ({exc})")
        if attempt < ATTEMPTS:
            # Brief pause: some CDNs answer with transient 403/5xx on a
            # freshly opened connection and succeed on a spaced retry.
            time.sleep(1)
            continue
    raise last_error


def request_json(url, *, json_body=None, form=None, headers=None,
                 timeout=DEFAULT_TIMEOUT):
    """Fetch JSON from url. GET by default; POST when json_body/form given.

    Retries once on failure. Raises SourceError with a clear message.
    """
    raw = _request(url, json_body=json_body, form=form, headers=headers,
                   timeout=timeout)
    try:
        return json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError:
        raise SourceError(f"invalid JSON returned by {url}") from None


def request_text(url, *, headers=None, timeout=DEFAULT_TIMEOUT):
    """Fetch plain text from url (GET). Raises SourceError on failure."""
    raw = _request(url, headers=headers, timeout=timeout)
    return raw.decode("utf-8", errors="replace")
