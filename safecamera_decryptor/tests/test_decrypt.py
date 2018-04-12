import pytest

from safecamera_decryptor.decrypt import CorruptOrInvalidPassword, Decryptor


def join(seq):
    return b''.join(seq)


def test_happy_path(test_dot_png):
    decryptor = Decryptor('test_password')
    assert join(decryptor.decrypt(test_dot_png)) == b'test.png'


def test_invalid_password(test_dot_png):
    decryptor = Decryptor('wrong password')
    with pytest.raises(CorruptOrInvalidPassword):
        join(decryptor.decrypt(test_dot_png))


def test_corrupt_data_correct_password(test_dot_png):
    decryptor = Decryptor('test_password')
    test_dot_png.content = b'some garbage'
    with pytest.raises(CorruptOrInvalidPassword):
        join(decryptor.decrypt(test_dot_png))
