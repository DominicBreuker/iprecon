import io
import contextlib

import ipaddress
from iprecon.ip import IPAddress
from iprecon.output import CSVWriter


def test_csvwriter():
    tests = [
        {
            "testname": "just an IP",
            "data": [
                {"ip": "1.2.3.4", "whois_info": {}},
            ],
            "expected": """
ip,network,asn,all_networks
1.2.3.4,None,None,
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
ip,network,asn,all_networks
1.2.3.4,1.2.3.0/24[asn-12345],1.2.3.0/24[asn-12345],
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
ip,network,asn,all_networks
1.2.3.4,1.2.3.0/28[a subnet],1.2.3.0/24[asn-12345],1.2.3.0/28[a subnet]
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
ip,network,asn,all_networks
1.2.3.4,1.2.3.0/28[netname 12345678901234567890123456789012345678901234567890123456789012345678901234567890],1.2.3.0/24[asn-12345],1.2.3.0/28[netname 12345678901234567890123456789012345678901234567890123456789012345678901234567890]
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
ip,network,asn,all_networks
1.2.3.4,1.2.3.0/28[netname 123 456 789 2 718--],1.2.3.0/24[asn-12345],1.2.3.0/28[netname 123 456 789 2 718--]
""",
        },  # remove all characters that mess up the CSV
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
            output = CSVWriter()
            for ip in ips:
                output.write(ip)

        actual = stdout.getvalue()
        expected = test["expected"].lstrip()

        assert (
            actual == expected
        ), f"CSVWriter for test ({test['testname']} wrong:\n##########\n{actual}\n##########\n{expected}"
