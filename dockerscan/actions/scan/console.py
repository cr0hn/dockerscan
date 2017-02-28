import logging

from dockerscan import get_log_level, run_in_console

from .api import *
from .model import *

log = logging.getLogger('dockerscan')


def launch_dockerscan_scan_in_console(config: DockerScanModel):
    """Launch in console mode"""

    log.setLevel(get_log_level(config.verbosity))

    with run_in_console(config.debug):
        run_scan_dockerscan(config)

__all__ = ("launch_dockerscan_scan_in_console",)
