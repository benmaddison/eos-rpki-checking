# EOS RPKI Check

Arista EOS appears to mark an abnormal number of prefixes as `Invalid`.

This script will connect to an EOS device running a supported version via
EAPI, and retrive the BGP Local-RIB (including the reported ROV validation
status of each path), and a copy of the VRP in the RIPE Validator format.

It will calculate the expected validation status locally and report dis-
agreements.

## Installation

```bash
$ python3 -m venv eos-rpki-checking-venv
$ cd eos-rpki-checking-venv
$ git clone https://github.com/benmaddison/eos-rpki-checking.git
$ cd eos-rpki-checking
$ pip install -r requirements.txt
```

## Usage

```
Usage: eos-rpki-check.py [OPTIONS] HOSTNAME

  Compare EOS validation status to the expected results.

Options:
  -u, --username TEXT    EAPI Username
  -p, --password TEXT    EAPI Password
  -a, --afi [ipv4|ipv6]  Address family
  -r, --print-roas       Print ROAs covering each prefix
  -m, --print-matches    Print matching prefixes
  -R, --remote-vrp-file  Get the VRP set from remote
  --vrp-url TEXT         URL of the JSON serialised VRP set
  --help                 Show this message and exit.
```
