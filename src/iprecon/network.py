from __future__ import annotations
import re
import ipaddress

from typing import Optional, Union, Any

from iprecon.utils import clean, truncate


class Network:
    def __init__(
        self, cidrs: list[str], name: Optional[str], description: Optional[str]
    ):
        self.cidrs = [ipaddress.ip_network(cidr) for cidr in cidrs]
        self.name = name
        self.description = description

    def shortname(self, max_len: int) -> str:
        return truncate(clean(self.name or self.description or "???"), max_len)

    def size(self) -> int:
        return sum([cidr.num_addresses for cidr in self.cidrs])

    def __contains__(
        self, ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address, None]
    ) -> bool:
        if isinstance(ip, ipaddress.IPv4Address) or isinstance(
            ip, ipaddress.IPv6Address
        ):
            for cidr in self.cidrs:
                if ip in cidr:
                    return True

        return False

    def string(self, max_len: int) -> str:
        prefix = f"{'-'.join([ str(cidr) for cidr in self.cidrs ])}["
        return prefix + self.shortname(max_len - len(prefix) - 1) + "]"

    def __str__(self) -> str:
        return self.string(0)
