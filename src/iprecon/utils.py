import re


def clean(s: str) -> str:
    s = s.replace("\n", " ")
    s = s.replace("\r", "")
    s = re.sub(r"[^\x00-\x7F]+", "", s)  # all non-ascii chars should go away
    s = s.strip()
    return s


def truncate(s: str, n: int) -> str:
    if len(s) > n and n > 0:
        return f"{s[:n-3]}..."
    return s
