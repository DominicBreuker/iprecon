import abc
import json
import shutil

from typing import Union
from enum import Enum

from iprecon.ip import IPAddress


class Writer(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def write(self, ip: IPAddress):
        raise NotImplementedError


class TextWriter(Writer):
    def __init__(self):
        terminal_size = shutil.get_terminal_size(fallback=(80, 40))
        self.max_width = terminal_size[0] if terminal_size[0] >= 80 else 80
        self._print_header()

    def _print_header(self):
        max_ip_size = 39  # IPv6, 8*4 + 7
        max_asn_size = 6  # just a guess
        max_net_size = self.max_width - max_ip_size - max_asn_size - 8  # the rest

        self.col_size = {
            1: max_ip_size,
            2: max_asn_size,
            3: max_net_size,
        }
        self._print("IP", "ASN", "Network")
        self._print(
            max_ip_size * "-", max_asn_size * "-", max_net_size * "-", margin="-"
        )

    def _print(self, col1: str, col2: str, col3: str, margin: str = " "):
        col1 = right_justify(col1, self.col_size[1])
        col2 = right_justify(col2, self.col_size[2])
        col3 = left_justify(col3, self.col_size[3])
        print(f"|{col1}{margin}|{margin}{col2}{margin}|{margin}{col3}|")

    def write(self, ip):
        network = ip.network()
        net = network.string(max_len=self.col_size[3]) if network else "???"
        self._print(str(ip), str(ip.as_number() or "???"), net)


def right_justify(s: str, n: int) -> str:
    return f"{{0:>{n}s}}".format(s)


def left_justify(s: str, n: int) -> str:
    return f"{{0:<{n}s}}".format(s)


class CSVWriter(Writer):
    def __init__(self):
        self._print_header()

    def _print_header(self):
        self._print("ip", "network", "asn", "all_networks")

    def _print(self, *cols: str):
        sep = ","
        out = [c.replace(sep, " ") for c in cols]
        print(sep.join(out))

    def write(self, ip):
        all_networks = sorted(ip.networks(), key=lambda network: network.size())
        self._print(
            str(ip),
            str(ip.network()),
            str(ip.asn()),
            "|".join([str(n) for n in all_networks]),
        )


class JSONWriter(Writer):
    def write(self, ip):
        all_networks = sorted(ip.networks(), key=lambda network: network.size())
        print(
            json.dumps(
                {
                    "ip": str(ip),
                    "asn": str(ip.as_number()),
                    "asn_cidr": str(ip.as_cidr()),
                    "networks": [
                        {
                            "cidr": "-".join(str(cidr) for cidr in net.cidrs),
                            "name": str(net.name),
                            "description": str(net.description),
                        }
                        for net in all_networks
                    ],
                }
            )
        )


class OutputFormat(Enum):
    text = "text"
    csv = "csv"
    json = "json"

    def get_writer(self) -> Union[TextWriter, CSVWriter, JSONWriter]:
        if self.value == str(OutputFormat.csv):
            return CSVWriter()
        if self.value == str(OutputFormat.json):
            return JSONWriter()
        return TextWriter()

    def __str__(self):
        return self.value
