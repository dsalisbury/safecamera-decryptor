import pytest

from safecamera_decryptor.decrypt import (
    CipherParams, CorruptOrInvalidPassword, Decryptor, FilenameProvider)


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


iv = '30313233343536373839616263646566'
salt = '6661636563616665666163656361666566616365636166656661636563616665'
payload = '39383736353433323130'


@pytest.mark.parametrize('path', (
    f'zzSC-1_{iv}{salt}{payload}.sc',
    f'/a/b/c/d/e/f/zzSC-1_{iv}{salt}{payload}.sc',
    f'zzSC-1_{iv}{salt}{payload}.sc.someotherthinghere',
))
def test_filename_provider_happy_path(path):
    prov = FilenameProvider(path=path)
    assert prov.get_params() == CipherParams(
        salt=b'facecafe' * 4,
        iv=b'0123456789abcdef',
    )
    assert join(prov.read()) == b'9876543210'


def test_filename_provider_unhappy_paths():
    with pytest.raises(ValueError):
        FilenameProvider(path='some garbage filename').get_params()

    with pytest.raises(ValueError):
        FilenameProvider(path='zzSC-1-NotARealHexDump.sc').get_params()
