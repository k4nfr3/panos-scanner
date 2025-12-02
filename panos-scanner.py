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
import re
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
import requests.exceptions
import urllib3
import urllib3.exceptions

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# timeout value in seconds
default_timeout = 2

# proxies = {
#   'https': 'http://127.0.0.1:8080',
# }

logging.basicConfig(
    format="%(asctime)s %(levelname)-8s [%(funcName)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)

logging.Formatter.converter = time.gmtime


def etag_to_datetime(etag: str) -> Optional[datetime.date]:
    """
    Convert an HTTP ETag value containing a hexadecimal epoch to a date.

    Returns None if the ETag value cannot be parsed.
    """
    try:
        if "-" in etag:
            epoch_hex = etag.split("-", 1)[0]
        else:
            epoch_hex = etag[-8:]
        epoch_int = int(epoch_hex, 16)
        return datetime.datetime.fromtimestamp(epoch_int).date()
    except (ValueError, OSError, OverflowError) as exc:
        logger.debug("Invalid ETag format %r: %s", etag, exc)
        return None


def last_modified_to_datetime(last_modified: str) -> Optional[datetime.date]:
    """
    Convert an HTTP Last-Modified header value to a date.

    Returns None if the value cannot be parsed.
    """
    try:
        # Strip timezone part (e.g. " GMT") to match the format string.
        return datetime.datetime.strptime(
            last_modified[:-4], "%a, %d %b %Y %X"
        ).date()
    except (ValueError, TypeError) as exc:
        logger.debug("Invalid Last-Modified format %r: %s", last_modified, exc)
        return None


DEFAULT_HEADERS: Dict[str, str] = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:54.0) "
        "Gecko/20100101 Firefox/54.0"
    ),
    "Connection": "close",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Upgrade-Insecure-Requests": "1",
}


def get_resource(
    session: requests.Session,
    target: str,
    resource: str,
    date_headers: dict,
    errors: tuple,
    very_verbose: bool = False,
) -> Optional[dict]:
    logger.debug(resource)
    try:
        resp = session.get(
            f"{target.rstrip('/')}/{resource}",
            timeout=default_timeout,
        )
        
        # Check status code before raising, so we have it available for logging
        if not resp.ok:
            status_code = resp.status_code
            logger.warning("%s : Error %s", "HTTPError", status_code)
            return None
        
        # Print all headers in very verbose mode
        if very_verbose:
            logger.info("Response headers for %s/%s:", target, resource)
            for header_name, header_value in resp.headers.items():
                logger.debug("  %s: %s", header_name, header_value)
        
        return {
            h: resp.headers[h].strip('"') for h in date_headers if h in resp.headers
        }

    except requests.exceptions.HTTPError as e:
        # Fallback: try to get status code from exception if available
        status_code = getattr(e.response, 'status_code', None) if hasattr(e, 'response') and e.response else "Unknown"
        logger.warning("%s : Error %s", type(e).__name__, status_code)
        return None
    except requests.exceptions.ReadTimeout as e:
        logger.warning(type(e).__name__)
        return None
    except errors as e:
        raise e


def load_version_table(version_table: str) -> Dict[str, datetime.date]:
    """
    Load version table from a text file.
    
    Expected format: VERSION Mon DD YYYY (one per line)
    Example: 10.0.0 Jan 15 2020
    
    Returns a dictionary mapping version strings to dates.
    Skips malformed lines and logs warnings.
    """
    version_dict: Dict[str, datetime.date] = {}
    try:
        with open(version_table, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, start=1):
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith("#"):
                    continue
                
                parts = line.split()
                if len(parts) < 4:  # Need at least: version + month + day + year
                    logger.warning(
                        "Skipping line %d in %s: insufficient fields (expected: VERSION Mon DD YYYY): %r",
                        line_num,
                        version_table,
                        line,
                    )
                    continue
                
                try:
                    version = parts[0]
                    date_str = " ".join(parts[1:4])  # Take only month, day, year
                    date_obj = datetime.datetime.strptime(date_str, "%b %d %Y").date()
                    version_dict[version] = date_obj
                except ValueError as e:
                    logger.warning(
                        "Skipping line %d in %s: invalid date format (expected: Mon DD YYYY): %r - %s",
                        line_num,
                        version_table,
                        line,
                        e,
                    )
                    continue
    except FileNotFoundError:
        logger.error("Version table file not found: %s", version_table)
        raise
    except IOError as e:
        logger.error("Error reading version table file %s: %s", version_table, e)
        raise
    
    if not version_dict:
        logger.warning("No valid entries loaded from version table: %s", version_table)
    
    return version_dict


def check_date(version_table: Dict[str, datetime.date], date: datetime.date) -> List[dict]:
    matches: List[dict] = []
    for n in [0, 1, -1, 2, -2]:
        nearby_date = date + datetime.timedelta(n)
        versions = [
            version for version, v_date in version_table.items() if v_date == nearby_date
        ]
        if not versions:
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
            logger.debug(
                "Approximate version found for: %s",
                date.strftime('%d %b %Y'),
            )

    return matches


def get_matches(
    date_headers: dict,
    resp_headers: dict,
    version_table: Dict[str, datetime.date],
) -> Tuple[List[dict], Optional[str]]:
    unmatched_date: Optional[str] = None
    matches: List[dict] = []
    last_date: Optional[datetime.date] = None

    for header in date_headers.keys():
        if header in resp_headers:
            parser_name = date_headers[header]
            parser = globals().get(parser_name)
            if not callable(parser):
                logger.debug("No parser defined for header: %s", header)
                continue
            date = parser(resp_headers[header])
            if date is None:
                continue
            last_date = date
            matches.extend(check_date(version_table, date))

    if not matches and last_date is not None:
        logger.debug(
            "no matching for : %s",
            last_date.strftime('%b %d %Y'),
        )
        unmatched_date = last_date.strftime('%b %d %Y')

    return matches, unmatched_date



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


def get_targets_from_file(inputfile: str) -> List[str]:
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
    targets: List[str] = []
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


def get_cve_link(results: List[dict]) -> str:
    """
    Build a link to the PAN-OS security advisory page for a specific version,
    if an exact match is available. Returns an empty string otherwise.
    """
    base = "https://security.paloaltonetworks.com/?product=PAN-OS&sort=-cvss"
    for match in results:
        if match.get("precision") == "exact" and match.get("versions"):
            return f"{base}&version=PAN-OS+{match['versions'][0]}"
    return ""
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
    parser.add_argument(
        "-v",
        dest="verbose",
        action="count",
        default=0,
        help="verbose output (-v for verbose, -vv for very verbose with full headers)",
    )
    parser.add_argument("-s", dest="stop", action="store_true", help="stop after one exact match")
    parser.add_argument("-cve", dest="cve", action="store_true", help="Add link to official PAN security advisory page")
    parser.add_argument("-i", dest="insecure", action="store_true", help="Disable TLS certificate verification (NOT recommended).",)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-t", dest="target", help="https://gp.example.com or gp.example.com")
    group.add_argument("-f", dest="file", help="inputfile. One target per line. See target format")

    args = parser.parse_args()

    # Configure logging level based on CLI verbosity.
    # -v = DEBUG level, -vv = DEBUG level + print full headers
    very_verbose = args.verbose >= 2
    logger.setLevel(logging.DEBUG if args.verbose >= 1 else logging.ERROR)

    static_resources = [
        "login/images/favicon.ico",
        "global-protect/portal/images/bg.png",
        "global-protect/portal/css/login.css",
        "global-protect/prelogin.esp",
        "ssl-vpn/login.esp",
        "ssl-vpn/hipreportcheck.esp",
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
        # File-based targets are expected to already include scheme and trailing slash.
        targets_to_scan = get_targets_from_file(args.file)
    else:
        # Normalize a single target: add https:// if no scheme is provided.
        raw_target = args.target.strip()
        if not raw_target.startswith(("http://", "https://")):
            raw_target = f"https://{raw_target}"
        targets_to_scan = [raw_target]

    if args.verbose >= 1:
        logger.debug("scanning : %d target(s)", len(targets_to_scan))
        logger.debug("scanning target: %s", targets_to_scan)

    # Reuse HTTP connections and centralize TLS behaviour.
    session = requests.Session()
    session.verify = not args.insecure
    session.headers.update(DEFAULT_HEADERS)

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
                    session,
                    target_to_scan,
                    resource,
                    date_headers,
                    target_errors,
                    very_verbose=very_verbose,
                )

            except target_errors as e:
                logger.error(f"could not connect to target: {type(e).__name__}")
                continue
            if resp_headers is None:
                continue
            if resp_headers:
                total_responses += len(resp_headers)
            # Convert date-related HTTP headers to a standardized format, and
            # store any matching version strings.
            resource_matches, unknown_version = get_matches(
                date_headers, resp_headers, version_table
            )
            logger.debug("resource_matches: %s", resource_matches)

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
        cve_link = get_cve_link(total_matches)
        if args.cve and cve_link != "":
            results = {"target": target_to_print, "match": {}, "all": total_matches, "cvelink": cve_link}
        else:
            results = {"target": target_to_print, "match": {}, "all": total_matches}
        if total_responses == 0:  # not a single answer
            logger.error("Web service is up but no URL returned an answer. Are you sure it has GlobalProtect active ? ")
            if args.verbose < 1:
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
