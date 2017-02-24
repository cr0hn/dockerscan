"""
This file contains utils and reusable functions
"""

import logging

from collections import namedtuple


def dict_to_obj(data):
    """
    Transform an input dict into a object.

    >>> data = dict(hello="world", bye="see you")
    >>> obj = dict_to_obj(data)
    >>> obj.hello
    'world'

    :param data: input dictionary data
    :type data: dict
    """
    assert isinstance(data, dict)

    if not data:
        return namedtuple("OBJ", [])

    obj = namedtuple("OBJ", list(data.keys()))

    return obj(**data)


def get_log_level(verbosity: int) -> int:
    verbosity *= 10

    if verbosity > logging.CRITICAL:
        verbosity = logging.CRITICAL

    if verbosity < logging.DEBUG:
        verbosity = logging.DEBUG

    return (logging.CRITICAL - verbosity) + 10


__all__ = ("dict_to_obj", "get_log_level")
