import sys


verbose = False


def set_verbose():
    global verbose
    verbose = True


def error(msg: str):
    if verbose:
        print(f"[!] {msg}", file=sys.stderr)
