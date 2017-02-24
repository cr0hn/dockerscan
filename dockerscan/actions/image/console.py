import os
import logging

from dockerscan import get_log_level, run_in_console

from .api import *
from .model import *
from ..helpers import display_results_console

log = logging.getLogger('dockerscan')


def launch_dockerscan_image_in_console(config: DockerImageModel):
    """Launch in console mode"""

    log.setLevel(get_log_level(config.verbosity))

    with run_in_console():

        log.console("Starting analyzing docker image...")
        log.console("Selected image: '{}'".format(
            os.path.basename(config.image_path)))

        results = run_analyze_dockerscan(config)

        # Display image summary
        log.console("Analysis finished. Results:")
        display_results_console(results, log)


__all__ = ("launch_dockerscan_image_in_console",)
