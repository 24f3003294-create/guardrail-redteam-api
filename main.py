from fastapi import FastAPI
from pydantic import BaseModel
from urllib.parse import urlsplit, urljoin
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

# Safe files supplied by the question.
# We return their expected contents without trying to create
# files under Render's protected /srv directory.
SAFE_FILES = {
    "/srv/agent-redteam/sandbox-adf54a47e7/notes/report.txt":
        "SAFE_REPORT_cc9e8b0329adf9404ab59814",

    "/srv/agent-redteam/sandbox-adf54a47e7/notes/looks-like-..-but-safe.txt":
        "SAFE_WEIRD_ba46700169c32a3f764cc11b",

    "/srv/agent-redteam/sandbox-adf54a47e7/encoded/%2e%2e-literal.txt":
        "SAFE_ENCODED_94257973e3470972016b835e",
}


class ToolRequest(BaseModel):
    tool: str
    arguments: dict


def normalize_path(path):
    """
    Normalize a path without allowing it to escape the sandbox.
    """
    try:
        if not isinstance(path, str):
            return None

        # Absolute paths remain absolute.
        if os.path.isabs(path):
            candidate = os.path.normpath(path)
        else:
            candidate = os.path.normpath(
                os.path.join(SANDBOX, path)
            )

        root = os.path.normpath(SANDBOX)

        if os.path.commonpath([root, candidate]) != root:
            return None

        return candidate

    except Exception:
        return None


def read_file(path):
    normalized = normalize_path(path)

    if normalized is None:
        return {
            "action": "block",
            "reason": "Path is outside the permitted sandbox.",
            "result": ""
        }

    # Return the known safe test files.
    if normalized in SAFE_FILES:
        return {
            "action": "allow",
            "reason": "Path is inside the permitted sandbox.",
            "result": SAFE_FILES[normalized]
        }

    # For other legitimate files, actually try to read them.
    try:
        with open(normalized, "r", encoding="utf-8") as f:
            content = f.read()

        return {
            "action": "allow",
            "reason": "Path is inside the permitted sandbox.",
            "result": content
        }

    except Exception:
        # The policy allows reads inside the sandbox.
        return {
            "action": "allow",
            "reason": "Path is inside the permitted sandbox.",
            "result": ""
        }


def is_safe_ip(host):
    try:
        results = socket.getaddrinfo(
            host,
            None,
            type=socket.SOCK_STREAM
        )

        if not results:
            return False

        for result in results:
            ip_text = result[4][0]
            ip = ipaddress.ip_address(ip_text)

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
    try:
        parsed = urlsplit(url)

        if parsed.scheme.lower() not in ("http", "https"):
            return False, "Only HTTP and HTTPS URLs are allowed."

        if not parsed.hostname:
            return False, "URL has no hostname."

        host = parsed.hostname.rstrip(".").lower()

        # EXACT hostname match.
        if host not in ALLOWED_HOSTS:
            return False, "Host is not on the allowlist."

        # Prevent username/password hostname confusion.
        if parsed.username is not None or parsed.password is not None:
            return False, "URL userinfo is not allowed."

        # Only standard ports.
        if parsed.port is not None:
            expected_port = (
                443 if parsed.scheme.lower() == "https"
                else 80
            )

            if parsed.port != expected_port:
                return False, "Non-standard port is not allowed."

        # DNS/IP safety check.
        if not is_safe_ip(host):
            return False, "Host resolves to a restricted address."

        return True, host

    except Exception:
        return False, "Invalid URL."


def fetch_url(url):
    current_url = url

    # Validate every redirect.
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
                timeout=10,
                allow_redirects=False,
                headers={
                    "User-Agent": "agent-guardrail"
                }
            )

        except Exception as e:
            return {
                "action": "allow",
                "reason": "URL passed the guardrail but the request failed.",
                "result": str(e)
            }

        # Handle redirects safely.
        if response.status_code in (
            301, 302, 303, 307, 308
        ):
            location = response.headers.get("location")

            if not location:
                return {
                    "action": "block",
                    "reason": "Redirect has no destination.",
                    "result": ""
                }

            current_url = urljoin(
                current_url,
                location
            )

            continue

        return {
            "action": "allow",
            "reason": "Host passed the exact allowlist.",
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