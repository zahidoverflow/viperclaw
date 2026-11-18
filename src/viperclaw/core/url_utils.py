"""URL normalization utilities (`viperclaw.core.url_utils`)."""

from __future__ import annotations


LOCAL_HOST_PREFIXES = ("localhost", "127.0.0.1", "0.0.0.0", "[::1]", "::1")


def normalize_url(raw_url: str, default_scheme: str = "https") -> str:
    """
    Normalize a target URL so specifying `https://` or `http://` is optional.

    - Preserves explicit `http://` or `https://` schemes.
    - Defaults local/loopback hosts (`localhost`, `127.0.0.1`, `0.0.0.0`, `[::1]`)
      and explicit `:80` targets to `http://`.
    - Defaults all other scheme-less hostnames/URLs to `https://`.
    """
    cleaned = (raw_url or "").strip()
    if not cleaned:
        return ""
    lower = cleaned.lower()
    if lower.startswith(("http://", "https://")):
        return cleaned
    if cleaned.startswith("//"):
        return f"{default_scheme}:{cleaned}"

    authority = cleaned.split("/", 1)[0].split("?", 1)[0].lower()
    host_only = authority.split(":", 1)[0]
    if host_only in LOCAL_HOST_PREFIXES or authority.endswith(":80"):
        return f"http://{cleaned}"
    return f"{default_scheme}://{cleaned}"
