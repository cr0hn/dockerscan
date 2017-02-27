import ssl
import socket
import logging

from typing import Union, Set
from urllib.parse import urlparse
from collections import defaultdict

import requests

from requests.exceptions import ConnectTimeout, ConnectionError

from ..core.model import SharedConfig
from ..core.exceptions import DockerscanTimeoutError

requests.packages.urllib3.disable_warnings()


def check_console_input_config(config: SharedConfig,
                               log: logging.Logger = None) -> bool:

    log = log or logging.getLogger(__package__.split(".", maxsplit=1)[0])

    # Check if config is valid
    if not config.is_valid:
        for prop, msg in config.validation_errors:

            log.critical("[!] '%s' property %s" % (prop, msg))
        return False

    return True


def sanitize_url(url: str, port: int = 5000, schema: str = "http") -> str:
    if ":" not in url:
        url = "{}:{}".format(url, port)

    if not url.startswith("http"):
        url = "http://{}".format(url)

    return url


def get_ssl_common_names(remote: str) -> set:
    """This function extract the Common Names from a SSL certificate"""

    # Extract info from URL
    scheme, hostname, *_ = urlparse(remote)

    if ":" in hostname:
        hostname, port = hostname.split(":")
        port = int(port)
    elif "https" == scheme:
        hostname, port = hostname, 443
    else:
        return set()

    ret = set()

    ctx = ssl.create_default_context()
    s = ctx.wrap_socket(socket.socket(), server_hostname="*")
    try:
        s.connect((hostname, port))
    except ssl.CertificateError as e:
        key = "match either of "
        msg = str(e)

        # Extract domain from SSL CN
        msg = msg[msg.index(key) + len(key):]

        # Clear
        domains = msg.replace("'", "").replace(" ", "")

        # Unify domains
        for domain in domains.split(","):
            if domain.startswith("*"):
                domain = domain[2:]

            ret.add(domain)
    except ssl.SSLError:
        pass

    return ret


def get_remote_registry_info(target: str) -> Union[Set,
                                                   DockerscanTimeoutError]:
    """
    This function does two things:

    - detect the remote registry version. Allowed returned values are: {1, 2}
    - detect if remote Docker Registry has enabled the authentication

    :return: a tuple as format: (REMOTE_VERSION, ENABLED_OR_NOT_AUTH)
    :rtype: tuple(int, bool)

    :raise DockerscanTimeoutError: If remote server reach a timeout
    """
    #
    # Check for verion 2
    #
    remote_version = 1
    enabled_auth = False

    try:
        r = requests.get("{}/v2/".format(target),
                         timeout=2,
                         allow_redirects=False,
                         verify=False)

        if r.status_code in (200, 401):
            if "registry/2.0" in r.headers["Docker-Distribution-Api-Version"]:
                remote_version = 2

            if r.status_code == 401:
                enabled_auth = True

        return remote_version, enabled_auth

    except (ConnectTimeout, ConnectionError) as e:
        raise DockerscanTimeoutError("Remote registry '{}' do not responds".
                                     format(target))


def display_results_console(results: dict, log):
    for prop, value in results.__dict__.items():
        # Do not put: "not value" because it will ignore entries
        # with value "False", and we want theres values
        if prop.startswith("_") or (not value and type(value) is not bool):
            continue

        pretty_prop = prop.capitalize().replace("_", " ")

        # List will be displayed different
        if type(value) in (list, set):
            log.console("  - {}:".format(pretty_prop))

            for p in value:
                log.console("      > {}".format(p))

        # Display dictionaries
        elif type(value) in (defaultdict, dict):
            log.console("  - {}:".format(pretty_prop))

            for p, v in value.items():
                if hasattr(v, "add"):
                    v = ",".join(v)
                log.console("      > {} = {}".format(p, v))

        # Plain properties
        else:
            if prop == "cmd":
                log.console("  - {}".format(pretty_prop))
                log.console("      > '{}'".format(value))
            else:
                log.console("  - {} = {}".format(pretty_prop, value))


__all__ = ("check_console_input_config", "get_remote_registry_info",
           "sanitize_url", "display_results_console")
