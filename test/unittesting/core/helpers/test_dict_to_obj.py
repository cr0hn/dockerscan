import pytest

from dockerscan.core.helpers import dict_to_obj


def test_dict_to_obj_response_ok():
    
    ret = dict_to_obj(dict(hello="world", bye="see you"))
    
    assert hasattr(ret, "hello")
    assert hasattr(ret, "bye")


def test_dict_to_obj_response_invalid_input():
    
    with pytest.raises(AssertionError):
        dict_to_obj(None)


def test_dict_to_obj_response_empty():
    
    assert issubclass(dict_to_obj({}), object)
