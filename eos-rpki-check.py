#!/usr/bin/env python
"""Compare reported origin validation status from EOS."""

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


def fetch_vrp(remote_vrp_file, url, node):
    """Fetch the current VRP set."""
    if remote_vrp_file:
        response = requests.get(url, headers={"Accept": "application/json"})
        response.raise_for_status()
        vrp_data = response.json()
    else:
        cmd = "show bgp rpki roa ipv4"
        vrp_data = node.enable([cmd])[0]["result"]
        print(vrp_data)
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


def compare_ov_state(vrp_tree, prefix, length, origin, status):
    """Compute and compare validation state."""
    if status == ROV_STATUS["notValidated"]:
        return True, ROV_STATUS["notValidated"], []
    covered = False
    expected_status = None
    covering_roas = search_covering_roas(vrp_tree, prefix)
    for roa in covering_roas:
        covered = True
        if length <= roa["maxLength"] and origin == roa["asn"]:
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


@click.command()
@click.argument("hostname")
@click.option("--username", "-u", help="EAPI Username",
              prompt=True, default=lambda: os.environ.get("USER", ""))
@click.option("--password", "-p", help="EAPI Password",
              prompt=True, hide_input=True)
@click.option("--remote-vrp-file", "-r", help="Get the VRP set from remote",
              is_flag=True)
@click.option("--vrp-url", help="URL of the JSON serialised VRP set",
              default="https://rpki-vc1.wolcomm.net/api/export.json")
def main(hostname, username, password, remote_vrp_file, vrp_url):
    """Compare EOS validation status to the expected results."""
    passed = 0
    failed = 0
    node = pyeapi.connect(host=hostname, username=username, password=password,
                          return_node=True)
    vrp_tree = fetch_vrp(remote_vrp_file, vrp_url, node)
    for n in range(256):
        cmd = f"show bgp ipv4 unicast {n}.0.0.0/8 longer-prefixes"
        data = node.enable([cmd])[0]
        for prefix, length, paths in iter_routes(data):
            for origin, status in paths:
                match, expected, roas = compare_ov_state(vrp_tree, prefix,
                                                         length, origin,
                                                         status)
                if match:
                    result = click.style(ROV_STATUS_NAME[status], fg="green")
                    passed += 1
                else:
                    result = click.style(f"{ROV_STATUS_NAME[status]} "
                                         f"(expected: "
                                         f"{ROV_STATUS_NAME[expected]})",
                                         fg="red")
                    failed += 1
                click.echo(f"{prefix:18} {origin:10} {result}")
    click.echo("Comparison results:")
    click.secho(f"  Passed: {passed}", fg="green")
    click.secho(f"  Failed: {failed}", fg="red")
    return


if __name__ == "__main__":
    rc = main()
    sys.exit(rc)
