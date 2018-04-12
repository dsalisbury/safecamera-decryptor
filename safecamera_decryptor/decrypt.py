"""
Implementation of logic for decrypting SafeCamera-encrypted files.

>>> from safecamera_decryptor.decrypt import Decryptor, FileContentProvider
>>> decryptor = Decryptor('password')
>>> provider = FileContentProvider('path/to/encrypted_file.png')
>>> with open('decrypted_file', 'wb') as output:
...     for chunk in decryptor.decrypt(provider):
...         output.write(chunk)

"""
from abc import ABCMeta, abstractmethod
import binascii
from collections import namedtuple
import hashlib
from os.path import basename
import re

from Crypto.Hash import SHA256
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from jasypt4py.generator import PKCS12ParameterGenerator

BACKEND = default_backend()

CipherParams = namedtuple('CipherParams', ('salt', 'iv'))

MAGIC_STRING_VALUE = b'SCAES\x01'
HEADER_MAGIC_STRING = len(MAGIC_STRING_VALUE)
IV_LENGTH = 16
SALT_LENGTH = 32
HEADER_LENGTH = HEADER_MAGIC_STRING + IV_LENGTH + SALT_LENGTH
FILENAME_HEADER_LENGTH = IV_LENGTH + SALT_LENGTH


def derive_cipher_key(password, salt, iterations=2048):
    """Derive the encryption key from a base password."""
    # we have to uppercase the password hash as that's what Java would do
    pw_hash = hashlib.sha512(password).hexdigest().upper()
    generator = PKCS12ParameterGenerator(SHA256)
    key, _ = generator.generate_derived_parameters(
        password=pw_hash,
        salt=salt,
        iterations=iterations)
    return key


def bsplit(bytestring, *lengths):
    """Split one bytestring into many bytestrings of given lengths."""
    offset = 0
    for length in lengths:
        yield bytestring[offset:offset + length]
        offset += length


class CorruptOrInvalidPassword(Exception):
    pass


class Decryptor:
    # pylint: disable=too-few-public-methods
    """A decryptor for SafeCamera-encrypted content."""

    def __init__(self, master_password):
        """
        :param master_password: the master password to use when decrypting
        """
        self.master_password = master_password.encode()

    def decrypt(self, provider):
        """
        Decrypt content from provider.

        :param provider: an object which implements the Provider interface
        """
        params = provider.get_params()
        key = derive_cipher_key(self.master_password, params.salt)
        cipher = Cipher(
            algorithms.AES(key), modes.CBC(params.iv), backend=BACKEND)
        decryptor = cipher.decryptor()
        pad_spec = padding.PKCS7(128)
        unpadder = pad_spec.unpadder()

        try:
            for chunk in provider.read():
                yield unpadder.update(decryptor.update(chunk))
            yield unpadder.update(decryptor.finalize()) + unpadder.finalize()
        except ValueError:
            raise CorruptOrInvalidPassword()


class _Provider(metaclass=ABCMeta):
    @abstractmethod
    def get_params(self):
        """Extract cipher parameters from the provider source."""

    @abstractmethod
    def read(self):
        """Return a generator which reads data from the provider source."""


class _FileBasedProvider(_Provider):
    # pylint: disable=abstract-method
    def __init__(self, *, path):
        """
        :param path: path to the file for decrypting
        """
        self.path = path


class FileContentProvider(_FileBasedProvider):
    """Provide content and metadata using the contents of a file at a path."""
    def __init__(self, *, chunksize=8192, **kwargs):
        """
        :param chunksize: the number of bytes to read at once from the file
        """
        super().__init__(**kwargs)
        self.chunksize = chunksize

    def get_params(self):
        """Extract cipher parameters from the provider source."""
        with open(self.path, 'rb') as src:
            header = src.read(HEADER_LENGTH)

        magic_string, cipher_iv, salt = list(
            bsplit(header, HEADER_MAGIC_STRING, IV_LENGTH, SALT_LENGTH))
        if magic_string != MAGIC_STRING_VALUE:
            raise ValueError(f'Invalid magic string: {magic_string:r}')
        return CipherParams(iv=cipher_iv, salt=salt)

    def read(self):
        """Return a generator which reads data from the provider source."""
        with open(self.path, 'rb') as src:
            src.seek(HEADER_LENGTH)
            while True:
                data = src.read(self.chunksize)
                if not data:
                    break
                yield data


class FilenameProvider(_FileBasedProvider):
    """Provide content and metadata using the filename of a file at a path."""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        filename = basename(self.path)
        match = re.match(r'zzSC-\d+_(?P<enc_part>[A-Za-z0-9]+)\.sc', filename)
        self._encrypted_part = binascii.a2b_hex(match.group('enc_part'))

    def get_params(self):
        """Extract cipher parameters from the provider source."""
        cipher_iv, salt = list(
            bsplit(self._encrypted_part, IV_LENGTH, SALT_LENGTH))
        return CipherParams(iv=cipher_iv, salt=salt)

    def read(self):
        """Return a generator which reads data from the provider source."""
        yield self._encrypted_part[FILENAME_HEADER_LENGTH:]
