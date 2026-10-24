"""Server-side telemetry derivation (User-Agent parsing). Values match the RBA dataset conventions."""

import re
from typing import Dict

_BROWSERS = [
    (r"HeadlessChrome", "HeadlessChrome"),
    (r"Edg(e|A|iOS)?/", "Edge"),
    (r"OPR/|Opera", "Opera"),
    (r"Firefox/|FxiOS", "Firefox"),
    (r"SamsungBrowser", "Samsung"),
    (r"Chrome/|CriOS", "Chrome"),
    (r"Safari/", "Safari"),
    (r"curl/", "curl"),
    (r"python-requests|python-urllib|aiohttp|httpx", "python-client"),
]


def parse_user_agent(user_agent: str) -> Dict[str, str]:
    ua = user_agent or ""
    browser = next((name for pattern, name in _BROWSERS if re.search(pattern, ua)), "Unknown")

    if re.search(r"Windows", ua):
        os_name = "Windows"
    elif re.search(r"Android", ua):
        os_name = "Android"
    elif re.search(r"iPhone|iPad|iPod|iOS", ua):
        os_name = "iOS"
    elif re.search(r"Mac OS X|Macintosh", ua):
        os_name = "Mac"
    elif re.search(r"CrOS", ua):
        os_name = "Chrome"
    elif re.search(r"Linux|X11", ua):
        os_name = "Linux"
    else:
        os_name = "Unknown"

    if re.search(r"bot|crawler|spider|curl/|python-|HeadlessChrome", ua, re.I):
        device = "bot"
    elif re.search(r"iPad|Tablet", ua):
        device = "tablet"
    elif re.search(r"Mobi|Android|iPhone", ua):
        device = "mobile"
    elif ua:
        device = "desktop"
    else:
        device = "unknown"
    return {"browser": browser, "os": os_name, "device_type": device}
