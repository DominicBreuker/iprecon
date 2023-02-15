import io
import sys
import signal
import argparse
import getpass

from iprecon.log import error, set_verbose
from iprecon.client import (
    RequestMethod,
    SimpleClient,
    SimpleWHOISClient,
    SimpleRDAPClient,
    BulkRDAPClient,
)
from iprecon.ip import is_valid_ip, is_private_ip
from iprecon.output import OutputFormat, Writer
from iprecon.utils import clean

from typing import TextIO

STOP = False


def handler(signum, frame):
    global STOP
    STOP = True


signal.signal(signal.SIGINT, handler)


def main():
    args = parse_args()

    if args.verbose:
        set_verbose()

    input = args.from_file or sys.stdin
    output = args.output.get_writer()

    if args.request_method == RequestMethod.rdap:
        lookup_rdap_whois_iteratively(input=input, output=output)
    elif args.request_method == RequestMethod.whois:
        lookup_legacy_whois_iteratively(input=input, output=output)
    elif args.request_method == RequestMethod.rdap_bulk:
        lookup_rdap_whois_bulk(input=input, output=output)
    else:
        raise Exception(
            "unexpected request method {args.request.method}"
        )  # should never happen


def lookup_legacy_whois_iteratively(input: TextIO, output: Writer):
    lookup_iteratively(SimpleWHOISClient(), input, output)


def lookup_rdap_whois_iteratively(input: TextIO, output: Writer):
    lookup_iteratively(SimpleRDAPClient(), input, output)


def lookup_iteratively(client: SimpleClient, input: TextIO, output: Writer):
    for line in input:
        if STOP:
            return
        try:
            s = clean(line)
            if skip_input(s):
                continue

            ip = client.get(s)
            output.write(ip)
        except Exception as e:
            error(f"Error for {line.strip()}: {e}")


def lookup_rdap_whois_bulk(input: TextIO, output: Writer):
    client = BulkRDAPClient()

    ips = []
    for line in input:
        if STOP:
            return

        s = clean(line)
        if skip_input(s):
            continue

        ips.append(s)

    if len(ips) > 0:
        results = client.get(ips)
        for ip in results:
            output.write(ip)


def skip_input(s: str) -> bool:
    if not is_valid_ip(s):
        error(f"{s} is not a valid IP address")
        return True

    if is_private_ip(s):
        error(f"{s} is a private IP address")
        return True

    return False


def parse_args():
    parser = argparse.ArgumentParser(
        description="""Retrieve WHOIS information about IP addresses.
Examples:
 - iprecon -f ips.txt
 - cat ips.txt | iprecon
""",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "-f",
        "--from-file",
        type=argparse.FileType("r"),
        help="File with IP addresses, one per line (IPs read from stdin if not given)",
    )
    parser.add_argument(
        "-m",
        "--request-method",
        type=RequestMethod,
        choices=list(RequestMethod),
        default=RequestMethod.rdap,
        help="Method to use for data collection. Can be legacy WHOIS, RDAP or bulk RDAP requests (experimental, only for huge lists)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=OutputFormat,
        choices=list(OutputFormat),
        default=OutputFormat.text,
        help=f"Format for output of result data",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="output status and error messages (default: False)",
    )

    return parser.parse_args()


if __name__ == "__main__":
    main()
