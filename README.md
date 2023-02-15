<h1 align="center">
  <img src="static/logo.png" width="60%" alt="iprecon">
  <br>
</h1>

<p align="center">
<a href="https://opensource.org/licenses/BSD-2-Clause"><img src="https://img.shields.io/badge/license-BSD%202--Clause-blue"></a>
</p>

<p align="center">
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#acknowledgements">Acknowledgements</a>
</p>

`iprecon` is a small CLI tool you can use to get WHOIS data for IP addresses which a focus on determining IP ownership.
Accepts lists of IPs from files or piped via stdin and outputs in different formats (textual table, CSV or JSON).
Output per IP is concise and kept to a single line for easy grepping and quick visual inspection.

# Installation

Run `pip install iprecon` to get it from [PyPI](https://pypi.org/).
Then run `iprecon --help` to see if it worked.

Alternatively, clone and install requirements from [requirements.txt](./requirements.txt)
(virtual environment highly recommended).

# Usage

To run `iprecon` you have to give it a list of IP addresses to check.
It expects simple lists with one IP per file.
Do it in two ways:
- from file: `iprecon --from-file /path/to/ips.txt`
- piped from stdin: `cat /path/to/ips.txt | iprecon`

You can output to different formats:
- `iprecon -o text`: outputs an ASCII table (terminal)
- `iprecon -o csv`: outputs a CSV file
- `iprecon -o json`: outputs a JSON file

Output is always printed to stdout.
Redirect to a file if required (e.g., `iprecon -o json > out.json` to store a JSON file).

Errors are ignored silently, e.g., if IPs have invalid formats or are private.
To see errors on stderr, request verbose output with `iprecon -v`.

WHOIS data can be requested in different ways.
Generally speaking, there is the legacy WHOIS protocol which is text-based and difficult to parse.
There is also RDAP, which is an HTTP-based protocol returning structured data.
See [here](https://www.arin.net/resources/registry/whois/rdap/) for more information.
By default, `iprecon` uses RDAP but if for any reason you get nonsense try if `iprecon --request-method whois` works better.

The tool is not fast and you may have to wait long when IP lists are large.
Try `iprecon --request-method rdap-bulk` in those cases, which tries to speed up but as much as possible but you may get banned.
There is also a delay because of setup so it will actually be slower on small lists.
You will also not get any intermediate output.
All results are shown at the end.

# Acknowledgements

`iprecon` is nothing more than a tiny wrapper around [github.com/secynic/ipwhois](https://github.com/secynic/ipwhois),
which is the library actually doing all the work.
Think of it as a command line interface to the library.
It has [nice documentation](https://ipwhois.readthedocs.io/en/latest/) you should read if you want to
know what is actually going on.


