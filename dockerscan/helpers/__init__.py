import logging

from contextlib import contextmanager

log = logging.getLogger("dockerscan")


@contextmanager
def run_in_console():
    try:
        yield
    except Exception as e:
        log.critical(" !! Unhandled exception: %s" % str(e))

        log.exception(" !! Unhandled exception: %s" % e, stack_info=True)
    finally:
        log.debug("Shutdown...")
