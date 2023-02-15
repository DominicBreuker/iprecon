import re
import ipaddress

from iprecon.network import Network

from typing import Optional, Union, Any


class IPAddress:
    def __init__(
        self,
        ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address],
        whois_info: Any,
        rdap_info: Any,
    ):
        self.ip = ip
        self.whois_info = whois_info or {}
        self.rdap_info = rdap_info or {}

    def as_number(self) -> Optional[int]:
        return self.rdap_info.get("asn") or self.whois_info.get("asn")

    def as_cidr(self) -> Optional[str]:
        return self.rdap_info.get("asn_cidr") or self.whois_info.get("asn_cidr")

    def asn(self) -> Optional[Network]:
        cidr = self.as_cidr()
        if not cidr or not is_valid_cidr(cidr):
            return None

        as_number = self.as_number()
        if not as_number:
            as_number = "?????"

        return Network(
            cidrs=[cidr],
            name=f"asn-{as_number}",
            description=None,
        )

    def has_rdap_info(self) -> bool:
        return len(self.rdap_info) > 0

    def networks(self) -> list[Network]:
        if self.has_rdap_info():
            return self._networks_rdap()
        else:
            return self._networks_whois()

    def _networks_whois(self) -> list[Network]:
        nets = [net for net in self.whois_info.get("nets", [])]

        out = []
        for net in nets:
            cidrs = [cidr.strip() for cidr in net.get("cidr", "").split(",")]
            if are_valid_cidrs(cidrs):
                out.append(
                    Network(
                        cidrs=cidrs,
                        name=net.get("name"),
                        description=net.get("description"),
                    )
                )

        return out

    def _networks_rdap(self) -> list[Network]:
        net = self.rdap_info.get("network", {})
        cidrs = [cidr.strip() for cidr in net.get("cidr", "").split(",")]
        if not are_valid_cidrs(cidrs):
            return []

        return [
            Network(
                cidrs=cidrs,
                name=net.get("name"),
                description=";".join(
                    [
                        f"{remark.get('title')}: {remark.get('description')}"
                        for remark in (net.get("remarks") or [])
                    ]
                ),
            )
        ]

    def network(self) -> Optional[Network]:
        networks = self.networks()

        networks = sorted(
            networks, key=lambda network: network.size()
        )  # smallest networks first

        # use ASN as fallback
        if len(networks) < 1:
            asn = self.asn()
            if asn:
                networks.append(asn)

        return networks[0] if networks else None

    def __str__(self) -> str:
        return str(self.ip)


def are_valid_cidrs(ss: list[str]) -> bool:
    for s in ss:
        if not is_valid_cidr(s):
            return False

    return True


def is_valid_cidr(s: str) -> bool:
    try:
        ipaddress.ip_network(s)
        return True
    except ValueError:
        return False


def is_valid_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def is_private_ip(s: str) -> bool:
    return ipaddress.ip_address(s).is_private
