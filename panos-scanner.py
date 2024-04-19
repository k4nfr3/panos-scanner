#!/usr/bin/env python3

"""
Developed with <3 by the Bishop Fox Continuous Attack Surface Testing (CAST) team.
https://www.bishopfox.com/continuous-attack-surface-testing/how-cast-works/

Author:     @noperator
Purpose:    Determine the software version of a remote PAN-OS target.
Notes:      - Requires version-table.txt in the same directory.
            - Usage of this tool for attacking targets without prior mutual
              consent is illegal. It is the end user's responsibility to obey
              all applicable local, state, and federal laws. Developers assume
              no liability and are not responsible for any misuse or damage
              caused by this program.
Usage:      python3 panos-scanner.py [-h] [-v] [-s] -t TARGET
"""

import argparse
import datetime
import json
import logging
import requests
import requests.exceptions
import time
import urllib3
import urllib3.exceptions
import re
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

verbose = False

# timeout value in seconds
default_timeout = 2

# proxies = {
#   'https': 'http://127.0.0.1:8080',
# }

# Set up logging.
logging.basicConfig(
    format="%(asctime)s %(levelname)-8s [%(funcName)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger(__name__)
if verbose:
    logger.setLevel(logging.INFO)
else:
    logger.setLevel(logging.ERROR)

logging.Formatter.converter = time.gmtime


def etag_to_datetime(etag: str) -> datetime.date:
    if etag.find('-'):
        epoch_hex = etag.split('-', 1)[0]
    else:
        epoch_hex = etag[-8:]
    try:
        answer = datetime.datetime.fromtimestamp(int(epoch_hex, 16)).date()
        toto = int(epoch_hex, 16)
    except :
        answer=""

    return answer


def last_modified_to_datetime(last_modified: str) -> datetime.date:
    return datetime.datetime.strptime(last_modified[:-4], "%a, %d %b %Y %X").date()


def get_resource(target: str, resource: str, date_headers: dict, errors: tuple) -> dict:
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:54.0) Gecko/20100101 Firefox/54.0",
        "Connection": "close",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Upgrade-Insecure-Requests": "1",
    }
    logger.debug(resource)
    try:
        resp = requests.get(
            "%s/%s" % (target, resource), headers=headers, timeout=default_timeout, verify=False
        )
        resp.raise_for_status()
        return {
            h: resp.headers[h].strip('"') for h in date_headers if h in resp.headers
        }

    except (requests.exceptions.HTTPError, requests.exceptions.ReadTimeout) as e:
        logger.warning(type(e).__name__)
        return None
    except errors as e:
        raise e


def load_version_table(version_table: str) -> dict:
    with open(version_table, "r") as f:
        entries = [line.strip().split() for line in f.readlines()]
    return {
        e[0]: datetime.datetime.strptime(" ".join(e[1:]), "%b %d %Y").date()
        for e in entries
    }


def check_date(version_table: dict, date: datetime.date) -> list:
    matches = []
    for n in [0, 1, -1, 2, -2]:
        nearby_date = date + datetime.timedelta(n)
        versions = [
            version for version, date in version_table.items() if date == nearby_date
        ]
        if not len(versions):
            continue
        precision = "exact" if n == 0 else "approximate"
        append = True
        for match in matches:
            if match["precision"] == precision:
                append = False
        if append:
            matches.append(
                {
                    "date": nearby_date,
                    "versions": versions,
                    "precision": precision
                }
            )
        if precision == 'approximate':
            logger.debug(f"Appromixate version found for : {date.strftime('%d %b %Y')}")

    return matches


def get_matches(date_headers: dict, resp_headers: dict, version_table: dict) -> list:
    unmatched_date=""
    matches = []
    for header in date_headers.keys():
        if header in resp_headers:
            date = globals()[date_headers[header]](resp_headers[header])
            if date != "":
                matches.extend(check_date(version_table, date))
    if len(matches) == 0 and 'date' in locals():  # if no matching but data return add as debug log
        logger.debug(f"no matching for : {date.strftime('%b %d %Y')}")
        unmatched_date = str(date.strftime('%b %d %Y'))
    return matches,unmatched_date



def strip_url(fullurl: str) -> str:
    """
    Extracts the host and port from a full URL and returns it.

    Args:
    fullurl (str): The full URL string.

    Returns:
    str: The host and port extracted from the URL.
    """
    parsed_url = urlparse(fullurl)
    # Combining the hostname and port if port is specified
    if parsed_url.port:
        return f"{parsed_url.hostname}:{parsed_url.port}"
    else:
        return parsed_url.hostname


def get_targets_from_file(inputfile: str):
    """
    Read lines from the input file and return valid targets in the format 'https://1.2.3.4/' or 'https://1.2.3.4:8889/'.

    Args:
    inputfile (str): Path to the input file.

    Returns:
    list: List of valid targets in the format 'https://1.2.3.4/' or 'https://1.2.3.4:8889/'.

    Raises:
    ValueError: If any line in the file does not match the specified format.
    IOError: If there's an error reading the input file.
    """
    targets = []
    try:
        with open(inputfile, 'r') as file:
            for line in file:
                line = line.strip()
                if re.match(r'^https://(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::\d+)?/$', line):
                    targets.append(line)
                else:
                    raise ValueError(f"Invalid format in line: {line}")
    except IOError as e:
        raise IOError(f"Error reading file: {e}")

    return targets

def get_cve_link(results):
    outputlink = "https://security.paloaltonetworks.com/?product=PAN-OS&sort=-cvss"
    for match in results:
        if match["precision"] == "exact":
            outputlink += "&version=PAN-OS+" + match["versions"][0]
            break
    return outputlink
def main():

    # Parse arguments.
    parser = argparse.ArgumentParser(
        description="""
            Determine the software version of a remote PAN-OS target. Requires
            version-table.txt in the same directory. See
            https://security.paloaltonetworks.com/?product=PAN-OS for security
            advisories for specific PAN-OS versions.
        """
    )
    parser.add_argument("-v", dest="verbose", action="store_true", help="verbose output")
    parser.add_argument("-s", dest="stop", action="store_true", help="stop after one exact match")
    parser.add_argument("-cve", dest="cve", action="store_true", help="Add link to official PAN security advisory page")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-t", dest="target", help="https://example.com")
    group.add_argument("-f", dest="file", help="inputfile. One target per line. See target format")

    args = parser.parse_args()

    static_resources = [
        "login/images/favicon.ico",
        "global-protect/portal/images/bg.png",
        "global-protect/portal/css/login.css",
        "js/Pan.js",
        "global-protect/portal/images/favicon.ico",
    ]

    version_table = load_version_table("version-table.txt")

    # The keys in "date_headers" represent HTTP response headers that we're
    # looking for. Each of those headers maps to a function in this namespace
    # that knows how to decode that header value into a datetime.
    date_headers = {
        "ETag": "etag_to_datetime",
        "Last-Modified": "last_modified_to_datetime",
    }

    # These errors are indicative of target-level issues. Don't continue
    # requesting other resources when encountering these; instead, bail.
    target_errors = (
        requests.exceptions.ConnectTimeout,
        requests.exceptions.SSLError,
        requests.exceptions.ConnectionError,
    )
    if args.file is not None:
        targets_to_scan = get_targets_from_file(args.file)
    else:
        targets_to_scan = [args.target]

    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug(f"scanning : {len(targets_to_scan)} target(s)")
        logger.debug(f"scanning target: {targets_to_scan}")

    # Let's scan each target
    for target_to_scan in targets_to_scan:

        # A match is a dictionary containing a date/version pair per target.
        total_matches = []

        # Total of responses per target
        total_responses = 0

        # returned date Etag if unmatched
        unknown_version = ""
        # Check for the presence of each static resource.
        for resource in static_resources:
            try:
                resp_headers = get_resource(
                    target_to_scan,
                    resource,
                    date_headers.keys(),
                    target_errors
                )

            except target_errors as e:
                logger.error(f"could not connect to target: {type(e).__name__}")
                continue
            if resp_headers == None:
                continue
            if len(resp_headers) > 0 :
                total_responses += len(resp_headers)
            # Convert date-related HTTP headers to a standardized format, and
            # store any matching version strings.
            resource_matches,unknown_version = get_matches(date_headers, resp_headers, version_table)
            for match in resource_matches:
                match["resource"] = resource
            total_matches.extend(resource_matches)

            # Stop if we've got an exact match.
            stop = False
            if args.stop:
                for match in resource_matches:
                    if match["precision"] == "exact":
                        stop = True
            if stop:
                continue

        # Print results.
        target_to_print = strip_url(target_to_scan)
        try:
            cve_link = get_cve_link(resource_matches)
        except:
            cve_link = ""
        if args.cve and cve_link != "":
            results = {"target": target_to_print, "match": {}, "all": total_matches, "cvelink": cve_link}
        else:
            results = {"target": target_to_print, "match": {}, "all": total_matches}
        if total_responses == 0:  # not a single answer
            logger.error("Web service is up but no URL returned an answer. Are you sure it has GlobalProtect active ? ")
            if not args.verbose:
                logger.error("Try adding -v option for more verbosity")
            continue

        if not len(total_matches):
            logger.error("no matching versions found for : " + target_to_scan)
            results = {"target": target_to_print, "unmatch": {}, "etag": unknown_version}

        else:
            closest = sorted(total_matches, key=lambda x: x["precision"], reverse=True)[0]
            results["match"] = closest

        print(json.dumps(results, default=str))


if __name__ == "__main__":
    main()
