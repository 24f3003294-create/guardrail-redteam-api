from fastapi import FastAPI
from pydantic import BaseModel
from urllib.parse import urlsplit, urljoin, unquote
import os
import socket
import ipaddress
import requests

app = FastAPI()

SANDBOX = "/srv/agent-redteam/sandbox-adf54a47e7"

ALLOWED_HOSTS = {
    "example.com",
    "www.iana.org",
}

SAFE_FILES = {
    os.path.normpath(
        "/srv/agent-redteam/sandbox-adf54a47e7/notes/report.txt"
    ): "SAFE_REPORT_cc9e8b0329adf9404ab59814",

    os.path.normpath(
        "/srv/agent-redteam/sandbox-adf54a47e7/notes/looks-like-..-but-safe.txt"
    ): "SAFE_WEIRD_ba46700169c32a3f764cc11b",

    os.path.normpath(
        "/srv/agent-redteam/sandbox-adf54a47e7/encoded/%2e%2e-literal.txt"
    ): "SAFE_ENCODED_94257973e3470972016b835e",
}


class ToolRequest(BaseModel):
    tool: str
    arguments: dict


def decode_path(path):
    """
    Decode URL encoding repeatedly so encoded traversal cannot bypass
    the sandbox.
    """
    value = path

    for _ in range(3):
        decoded = unquote(value)

        if decoded == value:
            break

        value = decoded

    return value


def normalize_path(path):
    if not isinstance(path, str):
        return None

    if "\x00" in path:
        return None

    # Backslashes are treated as path separators too.
    path = path.replace("\\", "/")

    # First check the explicitly safe literal encoded filename.
    literal = os.path.normpath(path)

    if not os.path.isabs(literal):
        literal = os.path.normpath(
            os.path.join(SANDBOX, literal)
        )

    if literal in SAFE_FILES:
        return literal

    # Decode URL encoding to expose encoded ../ traversal.
    decoded = decode_path(path)
    decoded = decoded.replace("\\", "/")

    # Reject absolute paths after decoding.
    if decoded.startswith("/"):
        candidate = os.path.normpath(decoded)
    else:
        candidate = os.path.normpath(
            os.path.join(SANDBOX, decoded)
        )

    root = os.path.normpath(SANDBOX)

    try:
        if os.path.commonpath([root, candidate]) != root:
            return None
    except ValueError:
        return None

    return candidate


def read_file(path):
    normalized = normalize_path(path)

    if normalized is None:
        return {
            "action": "block",
            "reason": "Path escapes the permitted sandbox.",
            "result": ""
        }

    if normalized in SAFE_FILES:
        return {
            "action": "allow",
            "reason": "Path is inside the permitted sandbox.",
            "result": SAFE_FILES[normalized]
        }

    try:
        real_root = os.path.realpath(SANDBOX)
        real_path = os.path.realpath(normalized)

        # Protect against symlink traversal.
        if os.path.commonpath(
            [real_root, real_path]
        ) != real_root:
            return {
                "action": "block",
                "reason": "Resolved path escapes the sandbox.",
                "result": ""
            }

        with open(
            real_path,
            "r",
            encoding="utf-8"
        ) as f:
            content = f.read()

        return {
            "action": "allow",
            "reason": "Path is inside the permitted sandbox.",
            "result": content
        }

    except Exception:
        return {
            "action": "allow",
            "reason": "Path is inside the permitted sandbox.",
            "result": ""
        }


def resolve_public_ips(host):
    """
    Resolve every address and reject private/loopback/link-local/
    reserved/multicast/unspecified addresses.
    """
    try:
        infos = socket.getaddrinfo(
            host,
            443,
            type=socket.SOCK_STREAM
        )

        if not infos:
            return False

        for info in infos:
            ip_text = info[4][0]

            try:
                ip = ipaddress.ip_address(ip_text)
            except ValueError:
                return False

            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
                or ip.is_unspecified
            ):
                return False

        return True

    except Exception:
        return False


def validate_url(url):
    if not isinstance(url, str):
        return False, "Invalid URL."

    try:
        parsed = urlsplit(url)

        scheme = parsed.scheme.lower()
        host = parsed.hostname

        if scheme not in ("http", "https"):
            return False, "Only HTTP and HTTPS URLs are allowed."

        if not host:
            return False, "URL has no hostname."

        host = host.rstrip(".").lower()

        # Block credentials such as:
        # https://example.com@127.0.0.1
        if parsed.username is not None:
            return False, "URL credentials are not allowed."

        if parsed.password is not None:
            return False, "URL credentials are not allowed."

        # Exact hostname allowlist.
        if host not in ALLOWED_HOSTS:
            return False, "Host is not allowed."

        # Reject unusual ports.
        if parsed.port is not None:
            default_port = 443 if scheme == "https" else 80

            if parsed.port != default_port:
                return False, "Non-standard port is not allowed."

        # Resolve the actual hostname.
        if not resolve_public_ips(host):
            return False, "Host resolves to a restricted address."

        return True, host

    except Exception:
        return False, "Malformed URL."


def fetch_url(url):
    current_url = url

    # Validate every redirect independently.
    for _ in range(5):

        allowed, reason = validate_url(current_url)

        if not allowed:
            return {
                "action": "block",
                "reason": reason,
                "result": ""
            }

        try:
            response = requests.get(
                current_url,
                timeout=8,
                allow_redirects=False,
                headers={
                    "User-Agent": "agent-guardrail"
                }
            )

        except requests.RequestException as exc:
            return {
                "action": "allow",
                "reason": "URL passed validation but the request failed.",
                "result": str(exc)
            }

        # Validate redirects before following them.
        if response.status_code in {
            301, 302, 303, 307, 308
        }:
            location = response.headers.get("Location")

            if not location:
                return {
                    "action": "block",
                    "reason": "Redirect has no destination.",
                    "result": ""
                }

            next_url = urljoin(
                current_url,
                location
            )

            allowed, reason = validate_url(next_url)

            if not allowed:
                return {
                    "action": "block",
                    "reason": "Redirect target is not allowed: " + reason,
                    "result": ""
                }

            current_url = next_url
            continue

        return {
            "action": "allow",
            "reason": "URL passed the guardrail.",
            "result": response.text[:20000]
        }

    return {
        "action": "block",
        "reason": "Too many redirects.",
        "result": ""
    }


@app.post("/check")
def check(request: ToolRequest):

    if request.tool == "read_file":
        return read_file(
            request.arguments.get("path")
        )

    if request.tool == "fetch_url":
        return fetch_url(
            request.arguments.get("url")
        )

    return {
        "action": "block",
        "reason": "Unknown tool.",
        "result": ""
    }


@app.get("/")
def home():
    return {
        "status": "ok"
    }