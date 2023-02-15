import ipaddress
from iprecon.ip import IPAddress, is_valid_ip, is_valid_cidr, is_private_ip


def test_whois_asn():
    tests = [
        {
            "ip": "1.2.3.4",
            "whois_info": {"asn": 12345, "asn_cidr": "1.2.3.0/24"},
            "expected": "1.2.3.0/24[asn-12345]",
        },
        {
            "ip": "1.2.3.4",
            "whois_info": {"asn": 12345, "asn_cidr": None},
            "expected": None,
        },
        {
            "ip": "1.2.3.4",
            "whois_info": {"asn": None, "asn_cidr": "1.2.3.0/24"},
            "expected": "1.2.3.0/24[asn-?????]",
        },
        {
            "ip": "1.2.3.4",
            "whois_info": {},
            "expected": None,
        },
        {
            "ip": "1.2.3.4",
            "whois_info": None,
            "expected": None,
        },
    ]

    for test in tests:
        ip = IPAddress(
            ip=ipaddress.IPv4Address(test["ip"]),
            whois_info=test["whois_info"],
            rdap_info={},
        )
        actual = ip.asn()
        expected = test["expected"]

        if actual:
            actual = str(actual)  # if we compare, then the string representation

        assert (
            actual == expected
        ), f"IPAddress({test['ip']}, {test['whois_info']}).as_cidr() = {actual} but should be {expected}"


def test_rdap_asn():
    tests = [
        {
            "ip": "1.2.3.4",
            "rdap_info": {"asn": 12345, "asn_cidr": "1.2.3.0/24"},
            "whois_info": None,
            "expected": "1.2.3.0/24[asn-12345]",
        },
        {
            "ip": "1.2.3.4",
            "rdap_info": {"asn": 12345, "asn_cidr": "1.2.3.0/24"},
            "whois_info": {"asn": 54321, "asn_cidr": "4.3.3.0/24"},
            "expected": "1.2.3.0/24[asn-12345]",  # RDAP has priority
        },
        {
            "ip": "1.2.3.4",
            "rdap_info": {"asn": 12345, "asn_cidr": None},
            "whois_info": None,
            "expected": None,
        },
        {
            "ip": "1.2.3.4",
            "rdap_info": {"asn": None, "asn_cidr": "1.2.3.0/24"},
            "whois_info": None,
            "expected": "1.2.3.0/24[asn-?????]",
        },
        {
            "ip": "1.2.3.4",
            "rdap_info": {},
            "whois_info": None,
            "expected": None,
        },
        {
            "ip": "1.2.3.4",
            "rdap_info": None,
            "whois_info": None,
            "expected": None,
        },
    ]

    for test in tests:
        ip = IPAddress(
            ip=ipaddress.IPv4Address(test["ip"]),
            whois_info=test["whois_info"],
            rdap_info=test["rdap_info"],
        )
        actual = ip.asn()
        expected = test["expected"]

        if actual:
            actual = str(actual)  # if we compare, then the string representation

        assert (
            actual == expected
        ), f"IPAddress({test['ip']}, {test['rdap_info']}).as_cidr() = {actual} but should be {expected}"


def test_as_number():
    tests = [
        {"ip": "1.2.3.4", "whois_info": {"asn": 12345}, "expected": 12345},
        {"ip": "1.2.3.4", "whois_info": {"asn": None}, "expected": None},
        {
            "ip": "1.2.3.4",
            "whois_info": {"asn": "12345"},
            "expected": "12345",
        },  # agnostivc of type
    ]

    for test in tests:
        ip = IPAddress(
            ip=ipaddress.IPv4Address(test["ip"]),
            whois_info=test["whois_info"],
            rdap_info={},
        )
        actual = ip.as_number()
        expected = test["expected"]
        assert (
            actual == expected
        ), f"IPAddress({test['ip']}, {test['whois_info']}).as_number() = {actual} but should be {expected}"


def test_as_cidr():
    tests = [
        {
            "ip": "1.2.3.4",
            "whois_info": {"asn_cidr": "1.2.3.0/24"},
            "expected": "1.2.3.0/24",
        },
        {
            "ip": "1.2.3.4",
            "whois_info": {"asn_cidr": None},
            "expected": None,
        },
    ]

    for test in tests:
        ip = IPAddress(
            ip=ipaddress.IPv4Address(test["ip"]),
            whois_info=test["whois_info"],
            rdap_info={},
        )
        actual = ip.as_cidr()
        expected = test["expected"]
        assert (
            actual == expected
        ), f"IPAddress({test['ip']}, {test['whois_info']}).as_cidr() = {actual} but should be {expected}"


def test_is_valid_ip():
    tests = [
        {"ip": "1.2.3.4", "expected": True},
        {"ip": "1111.2.3.4", "expected": False},
        {"ip": "1.2222.3.4", "expected": False},
        {"ip": "1.2.3333.4", "expected": False},
        {"ip": "1.2.3.4444", "expected": False},
        {"ip": "0.0.0.0", "expected": True},
        {"ip": "255.255.255.255", "expected": True},
        {"ip": "256.255.255.255", "expected": False},
        {"ip": "255.256.255.255", "expected": False},
        {"ip": "255.255.256.255", "expected": False},
        {"ip": "255.255.255.256", "expected": False},
        {"ip": "1..2.3.4", "expected": False},
    ]

    for test in tests:
        actual = is_valid_ip(test["ip"])
        expected = test["expected"]
        assert (
            actual == expected
        ), f"is_valid_ip({test['ip']}) = {actual} but should be {expected}"


def test_is_valid_cidr():
    tests = [
        {"cidr": "1.2.3.4/32", "expected": True},
        {"cidr": "1.2.3.0/24", "expected": True},
        {"cidr": "1.2.3.4/24", "expected": False},
        {"cidr": "1.2.3.4/0", "expected": False},
        {"cidr": "1.2.3.4/33", "expected": False},
        {"cidr": "1.2.3.4/-1", "expected": False},
        {"cidr": "1111.2.3.4/10", "expected": False},
        {"cidr": "1.2222.3.4/24", "expected": False},
        {"cidr": "1.2.3333.4/24", "expected": False},
        {"cidr": "1.2.3.4444/24", "expected": False},
        {"cidr": "1.2.3.999/24", "expected": False},
    ]

    for test in tests:
        actual = is_valid_cidr(test["cidr"])
        expected = test["expected"]
        assert (
            actual == expected
        ), f"is_valid_cidr({test['cidr']}) = {actual} but should be {expected}"


def test_is_private_ip():
    tests = [
        {"ip": "1.2.3.4", "expected": False},
        {"ip": "127.0.0.1", "expected": True},
        {"ip": "127.0.0.2", "expected": True},
        {"ip": "10.0.0.1", "expected": True},
        {"ip": "172.16.1.2", "expected": True},
        {"ip": "192.168.3.4", "expected": True},
    ]

    for test in tests:
        actual = is_private_ip(test["ip"])
        expected = test["expected"]
        assert (
            actual == expected
        ), f"is_private_ip({test['ip']}) = {actual} but should be {expected}"
