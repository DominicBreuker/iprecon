import io
import contextlib

import ipaddress
from iprecon.ip import IPAddress
from iprecon.output import TextWriter


def test_textwriter_whois():
    tests = [
        {
            "testname": "just an IP",
            "data": [
                {"ip": "1.2.3.4", "whois_info": {}},
            ],
            "expected": """
|                                     IP |    ASN | Network                    |
|----------------------------------------|--------|----------------------------|
|                                1.2.3.4 |    ??? | ???                        |
""",
        },
        {
            "testname": "IP with ASN infos but no network",
            "data": [
                {
                    "ip": "1.2.3.4",
                    "whois_info": {"asn": 12345, "asn_cidr": "1.2.3.0/24"},
                },
            ],
            "expected": """
|                                     IP |    ASN | Network                    |
|----------------------------------------|--------|----------------------------|
|                                1.2.3.4 |  12345 | 1.2.3.0/24[asn-12345]      |
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
|                                     IP |    ASN | Network                    |
|----------------------------------------|--------|----------------------------|
|                                1.2.3.4 |  12345 | 1.2.3.0/28[a subnet]       |
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
                                "description": "any desc",
                            }
                        ],
                    },
                },
            ],
            "expected": """
|                                     IP |    ASN | Network                    |
|----------------------------------------|--------|----------------------------|
|                                1.2.3.4 |  12345 | 1.2.3.0/28[any desc]       |
""",
        },  # falls back to description of network has no name
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
|                                     IP |    ASN | Network                    |
|----------------------------------------|--------|----------------------------|
|                                1.2.3.4 |  12345 | 1.2.3.0/28[netname 1234...]|
""",
        },
        {
            "testname": "IP with a very long ASN",
            "data": [
                {
                    "ip": "1.2.3.4",
                    "whois_info": {
                        "asn": 1234567890,
                        "asn_cidr": "1.2.3.0/24",
                        "nets": [
                            {
                                "cidr": "1.2.3.0/28",
                                "name": "netname",
                                "description": "any",
                            }
                        ],
                    },
                },
            ],
            "expected": """
|                                     IP |    ASN | Network                    |
|----------------------------------------|--------|----------------------------|
|                                1.2.3.4 | 1234567890 | 1.2.3.0/28[netname]        |
""",  # looks ugly for now
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
                                "name": "1\n2\r\n3\n2,718-❤-",
                                "description": "any",
                            }
                        ],
                    },
                },
            ],
            "expected": """
|                                     IP |    ASN | Network                    |
|----------------------------------------|--------|----------------------------|
|                                1.2.3.4 |  12345 | 1.2.3.0/28[1 2 3 2,718--]  |
""",
        },  # remove all characters that mess up the output
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
            output = TextWriter()
            for ip in ips:
                output.write(ip)

        actual = stdout.getvalue()
        expected = test["expected"].lstrip()

        assert (
            actual == expected
        ), f"TextWriter for whois-test '{test['testname']}' wrong:\n##########\n{actual}\n##########\n{expected}"


def test_textwriter_rdap():
    tests = [
        {
            "testname": "just an IP",
            "data": [
                {"ip": "1.2.3.4", "rdap_info": {}},
            ],
            "expected": """
|                                     IP |    ASN | Network                    |
|----------------------------------------|--------|----------------------------|
|                                1.2.3.4 |    ??? | ???                        |
""",
        },
        {
            "testname": "IP with ASN infos",
            "data": [
                {
                    "ip": "1.2.3.4",
                    "rdap_info": {"asn": 12345, "asn_cidr": "1.2.3.0/24"},
                },
            ],
            "expected": """
|                                     IP |    ASN | Network                    |
|----------------------------------------|--------|----------------------------|
|                                1.2.3.4 |  12345 | 1.2.3.0/24[asn-12345]      |
""",
        },
        {
            "testname": "IP with ASN and more specific network",
            "data": [
                {
                    "ip": "1.2.3.4",
                    "rdap_info": {
                        "asn": 12345,
                        "asn_cidr": "1.2.3.0/24",
                        "network": {
                            "cidr": "1.2.3.0/28",
                            "name": "a subnet",
                            "remarks": [
                                {
                                    "title": "remark1",
                                    "description": "just a description",
                                }
                            ],
                        },
                    },
                },
            ],
            "expected": """
|                                     IP |    ASN | Network                    |
|----------------------------------------|--------|----------------------------|
|                                1.2.3.4 |  12345 | 1.2.3.0/28[a subnet]       |
""",
        },
        {
            "testname": "IP with ASN and more specific network",
            "data": [
                {
                    "ip": "1.2.3.4",
                    "rdap_info": {
                        "asn": 12345,
                        "asn_cidr": "1.2.3.0/24",
                        "network": {
                            "cidr": "1.2.3.0/28",
                            "remarks": [
                                {
                                    "title": "remark1",
                                    "description": "just a description",
                                }
                            ],
                        },
                    },
                },
            ],
            "expected": """
|                                     IP |    ASN | Network                    |
|----------------------------------------|--------|----------------------------|
|                                1.2.3.4 |  12345 | 1.2.3.0/28[remark1: jus...]|
""",
        },  # falls back to description if network has no name
    ]

    for test in tests:
        ips = [
            IPAddress(
                ip=ipaddress.IPv4Address(e["ip"]),
                whois_info=None,
                rdap_info=e["rdap_info"],
            )
            for e in test["data"]
        ]
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            output = TextWriter()
            for ip in ips:
                output.write(ip)

        actual = stdout.getvalue()
        expected = test["expected"].lstrip()

        assert (
            actual == expected
        ), f"TextWriter for rdap-test '{test['testname']}' wrong:\n##########\n{actual}\n##########\n{expected}"
