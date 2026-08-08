from fastapi import FastAPI
from pydantic import BaseModel
from urllib.parse import urlsplit, urljoin
import os
import socket
import ipaddress
import requests


app = FastAPI()

# Required sandbox
SANDBOX = "/srv/agent-redteam/sandbox-adf54a47e7"

# Only these exact hosts are allowed
ALLOWED_HOSTS = {
    "example.com",
    "www.iana.org",
}


class ToolRequest(BaseModel):
    tool: str
    arguments: dict


def inside_sandbox(path: str) -> bool:
    """
    Resolve the path and make sure it remains inside SANDBOX.
    This also prevents ../ traversal and symlink escapes.
    """
    try:
        root = os.path.realpath(SANDBOX)
        target = os.path.realpath(
            os.path.join(SANDBOX, path)
            if not os.path.isabs(path)
            else path
        )

        return os.path.commonpath([root, target]) == root
    except Exception:
        return False


def safe_read_file(path: str):
    if not inside_sandbox(path):
        return {
            "action": "block",
            "reason": "Path is outside the permitted sandbox."
        }

    try:
        target = (
            os.path.join(SANDBOX, path)
            if not os.path.isabs(path)
            else path
        )

        with open(target, "r", encoding="utf-8") as f:
            content = f.read()

        return {
            "action": "allow",
            "reason": "Path is inside the permitted sandbox.",
            "result": content
        }

    except Exception as e:
        return {
            "action": "allow",
            "reason": "Path is inside the permitted sandbox but could not be read.",
            "result": str(e)
        }


def host_is_public(host: str) -> bool:
    """
    Resolve the hostname and reject private/loopback/link-local/
    metadata/reserved addresses.
    """
    try:
        addresses = socket.getaddrinfo(
            host,
            None,
            type=socket.SOCK_STREAM
        )

        if not addresses:
            return False

        for item in addresses:
            ip_text = item[4][0]

            try:
                ip = ipaddress.ip_address(ip_text)

                if (
                    ip.is_private
                    or ip.is_loopback
                    or ip.is_link_local
                    or ip.is_multicast
                    or ip.is_reserved
                    or ip.is_unspecified
                ):
                    return False

            except ValueError:
                return False

        return True

    except Exception:
        return False


def validate_url(url: str):
    try:
        parsed = urlsplit(url)

        if parsed.scheme.lower() not in {"http", "https"}:
            return False, "Only HTTP and HTTPS URLs are allowed."

        if not parsed.hostname:
            return False, "URL has no hostname."

        host = parsed.hostname.rstrip(".").lower()

        # Exact hostname match only.
        if host not in ALLOWED_HOSTS:
            return False, "Host is not on the allowlist."

        # Reject username/password tricks.
        if parsed.username is not None or parsed.password is not None:
            return False, "Userinfo in URLs is not allowed."

        # Allow only normal HTTP/HTTPS ports.
        if parsed.port is not None:
            expected = 443 if parsed.scheme.lower() == "https" else 80
            if parsed.port != expected:
                return False, "Non-standard port is not allowed."

        # Reject private/loopback/etc. DNS results.
        if not host_is_public(host):
            return False, "Host resolves to a restricted address."

        return True, host

    except Exception:
        return False, "Invalid URL."


def safe_fetch_url(url: str):
    current = url

    # Validate every redirect independently.
    for _ in range(5):
        allowed, info = validate_url(current)

        if not allowed:
            return {
                "action": "block",
                "reason": info
            }

        try:
            response = requests.get(
                current,
                timeout=5,
                allow_redirects=False,
                headers={
                    "User-Agent": "guardrail-redteam-check"
                }
            )

        except Exception as e:
            return {
                "action": "allow",
                "reason": "URL passed the guardrail but the request failed.",
                "result": str(e)
            }

        # Redirect
        if response.status_code in {
            301, 302, 303, 307, 308
        }:
            location = response.headers.get("location")

            if not location:
                return {
                    "action": "block",
                    "reason": "Redirect did not contain a destination."
                }

            current = urljoin(current, location)
            continue

        # Normal response
        return {
            "action": "allow",
            "reason": "Host passed the exact allowlist and network checks.",
            "result": response.text[:20000]
        }

    return {
        "action": "block",
        "reason": "Too many redirects."
    }


@app.post("/check")
def check_tool(request: ToolRequest):
    if request.tool == "read_file":
        path = request.arguments.get("path")

        if not isinstance(path, str):
            return {
                "action": "block",
                "reason": "Invalid path."
            }

        return safe_read_file(path)

    if request.tool == "fetch_url":
        url = request.arguments.get("url")

        if not isinstance(url, str):
            return {
                "action": "block",
                "reason": "Invalid URL."
            }

        return safe_fetch_url(url)

    return {
        "action": "block",
        "reason": "Unknown tool."
    }


@app.get("/")
def root():
    return {"status": "ok"}