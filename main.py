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


class ToolRequest(BaseModel):
    tool: str
    arguments: dict


def canonical_path(path: str):
    if not isinstance(path, str):
        return None

    if "\x00" in path:
        return None

    # Convert backslashes to normal separators.
    path = path.replace("\\", "/")

    # Decode repeatedly to expose encoded traversal.
    decoded = path
    for _ in range(5):
        new_value = unquote(decoded)

        if new_value == decoded:
            break

        decoded = new_value

    # Reject absolute paths.
    if decoded.startswith("/"):
        return None

    # Build candidate strictly under sandbox.
    candidate = os.path.abspath(
        os.path.join(SANDBOX, decoded)
    )

    root = os.path.abspath(SANDBOX)

    try:
        if os.path.commonpath([root, candidate]) != root:
            return None
    except ValueError:
        return None

    return candidate


def read_file(path):
    candidate = canonical_path(path)

    if candidate is None:
        return {
            "action": "block",
            "reason": "Path escapes the permitted sandbox.",
            "result": ""
        }

    root = os.path.realpath(SANDBOX)

    # Resolve symlinks before allowing access.
    real_candidate = os.path.realpath(candidate)

    try:
        if os.path.commonpath(
            [root, real_candidate]
        ) != root:
            return {
                "action": "block",
                "reason": "Resolved path escapes the sandbox.",
                "result": ""
            }
    except ValueError:
        return {
            "action": "block",
            "reason": "Invalid path.",
            "result": ""
        }

    try:
        with open(
            real_candidate,
            "r",
            encoding="utf-8"
        ) as f:
            content = f.read()

        return {
            "action": "allow",
            "reason": "Path is inside the permitted sandbox.",
            "result": content
        }

    except FileNotFoundError:
        return {
            "action": "allow",
            "reason": "Path is inside the permitted sandbox.",
            "result": ""
        }

    except Exception as e:
        return {
            "action": "allow",
            "reason": "Path is inside the permitted sandbox.",
            "result": str(e)
        }


def is_public_ip(host):
    try:
        addresses = socket.getaddrinfo(
            host,
            443,
            type=socket.SOCK_STREAM
        )

        if not addresses:
            return False

        for item in addresses:
            ip_text = item[4][0]
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
    if not isinstance(url, str):
        return False, "Invalid URL."

    try:
        parsed = urlsplit(url)

        # Only HTTPS.
        if parsed.scheme.lower() != "https":
            return False, "Only HTTPS URLs are allowed."

        host = parsed.hostname

        if not host:
            return False, "Missing hostname."

        host = host.rstrip(".").lower()

        # Block userinfo tricks:
        # https://example.com@127.0.0.1
        if parsed.username is not None:
            return False, "URL credentials are not allowed."

        if parsed.password is not None:
            return False, "URL credentials are not allowed."

        # Reject explicit non-default ports.
        try:
            port = parsed.port
        except ValueError:
            return False, "Invalid port."

        if port is not None and port != 443:
            return False, "Non-standard ports are not allowed."

        # Exact host allowlist.
        if host not in ALLOWED_HOSTS:
            return False, "Host is not allowed."

        # Check DNS result.
        if not is_public_ip(host):
            return False, "Host resolves to a restricted address."

        return True, host

    except Exception:
        return False, "Malformed URL."


def fetch_url(url):
    current = url

    # Limit redirects.
    for _ in range(5):

        allowed, reason = validate_url(current)

        if not allowed:
            return {
                "action": "block",
                "reason": reason,
                "result": ""
            }

        try:
            response = requests.get(
                current,
                timeout=8,
                allow_redirects=False,
                headers={
                    "User-Agent": "agent-guardrail"
                }
            )

        except requests.RequestException as e:
            return {
                "action": "allow",
                "reason": "URL passed validation but request failed.",
                "result": str(e)
            }

        # Redirect must be validated BEFORE following it.
        if response.status_code in (
            301,
            302,
            303,
            307,
            308
        ):
            location = response.headers.get("Location")

            if not location:
                return {
                    "action": "block",
                    "reason": "Invalid redirect.",
                    "result": ""
                }

            next_url = urljoin(
                current,
                location
            )

            allowed, reason = validate_url(next_url)

            if not allowed:
                return {
                    "action": "block",
                    "reason": "Redirect target blocked: " + reason,
                    "result": ""
                }

            current = next_url
            continue

        return {
            "action": "allow",
            "reason": "URL passed validation.",
            "result": response.text[:20000]
        }

    return {
        "action": "block",
        "reason": "Too many redirects.",
        "result": ""
    }


@app.post("/check")
def check(request: ToolRequest):

    tool = request.tool
    args = request.arguments or {}

    if tool == "read_file":
        return read_file(args.get("path"))

    if tool == "fetch_url":
        return fetch_url(args.get("url"))

    return {
        "action": "block",
        "reason": "Unknown tool.",
        "result": ""
    }


@app.get("/")
def root():
    return {
        "status": "ok"
    }