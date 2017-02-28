import logging

from contextlib import contextmanager

log = logging.getLogger("dockerscan")


@contextmanager
def run_in_console(debug=False):
    try:
        yield
    except Exception as e:
        log.critical(" !! {}".format(e))

        if debug:
            log.exception(" !! Unhandled exception: %s" % e, stack_info=True)
    finally:
        log.debug("Shutdown...")
