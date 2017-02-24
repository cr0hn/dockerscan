import pytest

from dockerscan.actions.default.api import run_default_dockerscan


def test_run_default_dockerscan_runs_ok():

    #
    # FILL THIS WITH A TEST
    #
    # assert run_default_dockerscan() is None
    pass


def test_run_default_dockerscan_empty_input():

    with pytest.raises(AssertionError):
        run_default_dockerscan(None)
