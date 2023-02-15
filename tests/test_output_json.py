import io
import contextlib

import ipaddress
from iprecon.ip import IPAddress
from iprecon.output import JSONWriter


def test_jsonwriter():
    tests = [
        {
            "testname": "just an IP",
            "data": [
                {"ip": "1.2.3.4", "whois_info": {}},
            ],
            "expected": """
{"ip": "1.2.3.4", "asn": "None", "asn_cidr": "None", "networks": []}
""",
        },
        {
            "testname": "IP with ASN infos",
            "data": [
                {
                    "ip": "1.2.3.4",
                    "whois_info": {"asn": 12345, "asn_cidr": "1.2.3.0/24"},
                },
            ],
            "expected": """
{"ip": "1.2.3.4", "asn": "12345", "asn_cidr": "1.2.3.0/24", "networks": []}
""",
        },
        {
            "testname": "IP with ASN and more specific network",
            "data": [
                {
                    "ip": "1.2.3.4",
                    "whois_info": {
                        "asn": 12345,
                        "asn_cidr": "1.2.3.0/24",
                        "nets": [
                            {
                                "cidr": "1.2.3.0/28",
                                "name": "a subnet",
                                "description": "any",
                            }
                        ],
                    },
                },
            ],
            "expected": """
{"ip": "1.2.3.4", "asn": "12345", "asn_cidr": "1.2.3.0/24", "networks": [{"cidr": "1.2.3.0/28", "name": "a subnet", "description": "any"}]}
""",
        },
        {
            "testname": "IP with ASN and very long name",
            "data": [
                {
                    "ip": "1.2.3.4",
                    "whois_info": {
                        "asn": 12345,
                        "asn_cidr": "1.2.3.0/24",
                        "nets": [
                            {
                                "cidr": "1.2.3.0/28",
                                "name": "netname 12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                                "description": "any",
                            }
                        ],
                    },
                },
            ],
            "expected": """
{"ip": "1.2.3.4", "asn": "12345", "asn_cidr": "1.2.3.0/24", "networks": [{"cidr": "1.2.3.0/28", "name": "netname 12345678901234567890123456789012345678901234567890123456789012345678901234567890", "description": "any"}]}
""",
        },
        {
            "testname": "IP with ASN and name containing problematic characters",
            "data": [
                {
                    "ip": "1.2.3.4",
                    "whois_info": {
                        "asn": 12345,
                        "asn_cidr": "1.2.3.0/24",
                        "nets": [
                            {
                                "cidr": "1.2.3.0/28",
                                "name": "netname 123\n456\r\n789\n2,718-❤-",
                                "description": "any",
                            }
                        ],
                    },
                },
            ],
            "expected": """
{"ip": "1.2.3.4", "asn": "12345", "asn_cidr": "1.2.3.0/24", "networks": [{"cidr": "1.2.3.0/28", "name": "netname 123\\n456\\r\\n789\\n2,718-\\u2764-", "description": "any"}]}
""",
        },  # encodes your special characters
    ]

    for test in tests:
        ips = [
            IPAddress(
                ip=ipaddress.IPv4Address(e["ip"]),
                whois_info=e["whois_info"],
                rdap_info={},
            )
            for e in test["data"]
        ]
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            output = JSONWriter()
            for ip in ips:
                output.write(ip)

        actual = stdout.getvalue()
        expected = test["expected"].lstrip()

        assert (
            actual == expected
        ), f"CSVWriter for test ({test['testname']} wrong:\n##########\n{actual}\n##########\n{expected}"
