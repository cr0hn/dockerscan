import os
import logging

from dockerscan import get_log_level, run_in_console

from .api import *
from .model import *

log = logging.getLogger('dockerscan')


def launch_dockerscan_image_modify_trojanize_in_console(
        config: DockerImageInfoModifyTrojanizeModel):
    """Launch in console mode"""

    log.setLevel(get_log_level(config.verbosity))

    with run_in_console(config.debug):

        log.console("Starting analyzing docker image...")
        log.console("Selected image: '{}'".format(
            os.path.basename(config.image_path)))

        run_image_modify_trojanize_dockerscan(config)

        log.console("Image troyanized successful")


__all__ = ("launch_dockerscan_image_modify_trojanize_in_console", )
