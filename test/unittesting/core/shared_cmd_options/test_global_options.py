import pytest

from dockerscan.core.shared_cmd_options import global_options


def test_global_options_runs_ok():
    
    c = global_options()
    
    assert callable(c.__call__(lambda x: x)) is True


def test_global_options_check_input_params():
    
    with pytest.raises(AssertionError):
        global_options(None)
