import abc
import ipaddress
import ipwhois
import ipwhois.experimental

from iprecon.ip import IPAddress

from typing import Optional, Union, Any
from enum import Enum

# from pprint import PrettyPrinter


class SimpleClient(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def get(self, ip: str) -> IPAddress:
        raise NotImplementedError


class SimpleWHOISClient(SimpleClient):
    def get(self, ip: str) -> IPAddress:
        ipobj = ipaddress.ip_address(ip)
        whois_info = ipwhois.IPWhois(ip).lookup_whois()

        # pp = PrettyPrinter()
        # pp.pprint(whois_info)

        return IPAddress(ip=ipobj, whois_info=whois_info, rdap_info=None)


class SimpleRDAPClient(SimpleClient):
    def get(self, ip: str) -> IPAddress:
        ipobj = ipaddress.ip_address(ip)
        rdap_info = ipwhois.IPWhois(ip).lookup_rdap()

        # pp = PrettyPrinter()
        # pp.pprint(rdap_info)

        return IPAddress(ip=ipobj, whois_info=None, rdap_info=rdap_info)


class BulkRDAPClient:
    def get(self, ips: list[str]) -> list[IPAddress]:
        results, stats = ipwhois.experimental.bulk_lookup_rdap(addresses=ips)

        out = [
            IPAddress(ip=ipaddress.ip_address(ip), whois_info=None, rdap_info=rdap_info)
            for ip, rdap_info in results.items()
        ]

        # pp = PrettyPrinter()
        # pp.pprint(results)

        return out


class RequestMethod(Enum):
    whois = "whois"
    rdap = "rdap"
    rdap_bulk = "rdap-bulk"

    def __str__(self):
        return self.value
