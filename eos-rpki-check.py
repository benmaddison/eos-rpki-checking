#!/usr/bin/env python
"""Compare reported origin validation status from EOS."""

import collections
import ipaddress
import os
import re
import sys

import pyeapi
import requests
import click
import radix


ROV_STATUS = {
    "notValidated": -1,
    "notFound": 0,
    "valid": 1,
    "invalid": 2
}
ROV_STATUS_NAME = {v: k for k, v in ROV_STATUS.items()}

BATCHES = {
    "ipv4": (str(n)
             for n in ipaddress.ip_network("0.0.0.0/0").subnets(new_prefix=6)),
    "ipv6": (str(n)
             for n in ipaddress.ip_network("2000::/3").subnets(new_prefix=8)),
}


def fetch_vrp(remote_vrp_file, url, node, afi):
    """Fetch the current VRP set."""
    if remote_vrp_file:
        response = requests.get(url, headers={"Accept": "application/json"})
        response.raise_for_status()
        vrp_data = response.json()
    else:
        cmd = f"show bgp rpki roa {afi}"
        vrp_data = node.enable([cmd])[0]["result"]
    vrp_tree = radix.Radix()
    for roa in vrp_data["roas"]:
        prefix = roa["prefix"]
        node = vrp_tree.search_exact(prefix)
        if node is None:
            node = vrp_tree.add(prefix)
            node.data["roas"] = list()
        node.data["roas"].append(roa)
    return vrp_tree


def origin_as(path_entry):
    """Get the origin AS of a path."""
    as_path = path_entry["asPathEntry"]["asPath"]
    try:
        origin = re.findall(r"\d+", as_path)[-1]
        return f"AS{origin}"
    except IndexError:
        return ""


def ov_status(path_entry):
    """Get the reported ROV status of a path."""
    return ROV_STATUS[path_entry["routeType"]["originValidity"]]


def iter_routes(routes_data, vrf="default"):
    """Iterate over the prefix/path_data pairs in a BRIB dump."""
    route_entries = routes_data["result"]["vrfs"][vrf]["bgpRouteEntries"]
    for prefix, data in route_entries.items():
        yield prefix, data["maskLength"], iter_paths(data["bgpRoutePaths"])


def iter_paths(path_data):
    """Iterate over the paths for a prefix in a BRIB dump."""
    for path_entry in path_data:
        yield origin_as(path_entry), ov_status(path_entry)


def search_covering_roas(vrp_tree, prefix):
    """Search VRP tree for covering ROAs."""
    roa_sets = vrp_tree.search_covering(prefix)
    return [roa for roa_set in roa_sets for roa in roa_set.data["roas"]]


def compare_roa(roa, origin, length):
    """Compare origin AS and prefix length against ROA."""
    if length > roa["maxLength"]:
        return False
    roa_origin = roa["asn"]
    if isinstance(roa_origin, int):
        roa_origin = f"AS{roa_origin}"
    if origin != roa_origin:
        return False
    return True


def compare_ov_state(vrp_tree, prefix, length, origin, status):
    """Compute and compare validation state."""
    if status == ROV_STATUS["notValidated"]:
        return True, ROV_STATUS["notValidated"], []
    covered = False
    expected_status = None
    covering_roas = search_covering_roas(vrp_tree, prefix)
    for roa in covering_roas:
        covered = True
        if compare_roa(roa, origin, length):
            expected_status = ROV_STATUS["valid"]
            break
    else:
        if covered:
            expected_status = ROV_STATUS["invalid"]
        else:
            expected_status = ROV_STATUS["notFound"]
    try:
        assert status == expected_status
    except AssertionError:
        return False, expected_status, covering_roas
    return True, expected_status, covering_roas


def result_line(match, prefix, origin, observed_status, expected_status):
    """Format result output line."""
    if match:
        color = "green"
    else:
        color = "red"
    result = click.style(f"observed: {ROV_STATUS_NAME[observed_status]:14} "
                         f"expected: {ROV_STATUS_NAME[expected_status]:14}",
                         fg=color)
    return f"{prefix:30} {origin:10} {result}"


def dump_roas(roas):
    """Format ROA set for output."""
    for roa in roas:
        click.echo(f"    {roa}")


def print_results(results):
    """Print results matrix."""
    click.echo(f"{'':14}| Expected:")
    click.echo("Observed:     | {}".format("".join([f"{i:>14}"
                                                    for i in ROV_STATUS])))
    for observed, o in ROV_STATUS.items():
        row = "{:14}| {}".format(observed,
                                 "".join([result_colored(results, o, e)
                                          for e in ROV_STATUS.values()]))
        click.echo(row)


def result_colored(results, observed, expected):
    """Return colored results counter."""
    counter = results[observed][expected]
    if not counter:
        color = "white"
    else:
        if observed == expected:
            color = "green"
        else:
            color = "red"
    return click.style(f"{results[observed][expected]:14}", fg=color)


@click.command()
@click.argument("hostname")
@click.option("--username", "-u", help="EAPI Username",
              prompt=True, default=lambda: os.environ.get("USER", ""))
@click.option("--password", "-p", help="EAPI Password",
              prompt=True, hide_input=True)
@click.option("--afi", "-a", help="Address family",
              type=click.Choice(["ipv4", "ipv6"]), default="ipv4")
@click.option("--print-roas", "-r", help="Print ROAs covering each prefix",
              is_flag=True)
@click.option("--print-matches", "-m", help="Print matching prefixes",
              is_flag=True)
@click.option("--remote-vrp-file", "-R", help="Get the VRP set from remote",
              is_flag=True)
@click.option("--vrp-url", help="URL of the JSON serialised VRP set",
              default="https://rpki-vc1.wolcomm.net/api/export.json")
def main(hostname, username, password, afi, print_roas, print_matches,
         remote_vrp_file, vrp_url):
    """Compare EOS validation status to the expected results."""
    passed = 0
    failed = 0
    results = collections.defaultdict(collections.Counter)
    node = pyeapi.connect(host=hostname, username=username, password=password,
                          return_node=True)
    vrp_tree = fetch_vrp(remote_vrp_file, vrp_url, node, afi)
    for network in BATCHES[afi]:
        cmd = f"show bgp {afi} unicast {network} longer-prefixes"
        data = node.enable([cmd])[0]
        for prefix, length, paths in iter_routes(data):
            for origin, status in paths:
                match, expected, roas = compare_ov_state(vrp_tree, prefix,
                                                         length, origin,
                                                         status)
                line = result_line(match, prefix, origin, status, expected)
                if match:
                    passed += 1
                    if print_matches:
                        click.echo(line)
                        if print_roas:
                            dump_roas(roas)
                else:
                    failed += 1
                    click.echo(line)
                    if print_roas:
                        dump_roas(roas)
                results[status][expected] += 1
    click.echo("Comparison results:")
    click.secho(f"  Passed: {passed}", fg="green")
    click.secho(f"  Failed: {failed}", fg="red")
    print_results(results)
    return


if __name__ == "__main__":
    rc = main()
    sys.exit(rc)
