import pytest

from safecamera_decryptor.decrypt import Decryptor


def join(seq):
    return b''.join(seq)


def test_happy_path(test_dot_png):
    decryptor = Decryptor('test_password')
    assert join(decryptor.decrypt(test_dot_png)) == b'test.png'
