import pytest

from dockerscan.core.logger import setup_logging


def test_setup_logging_runs_ok():
    assert setup_logging("blah") is None


def test_setup_logging_runs_null_as_name():
    
    with pytest.raises(AssertionError):
        setup_logging(None)


def test_setup_logging_runs_invalid_as_name():
    with pytest.raises(AssertionError):
        setup_logging(dict())
