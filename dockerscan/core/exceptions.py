class DockerscanError(Exception):
    pass


class DockerscanValueError(ValueError):
    pass


class DockerscanTypeError(TypeError):
    pass


class DockerscanTimeoutError(TypeError):
    pass


class DockerscanNotExitsError(TypeError):
    pass


__all__ = ("DockerscanError", "DockerscanValueError", "DockerscanTypeError",
           "DockerscanTimeoutError", "DockerscanNotExitsError")
