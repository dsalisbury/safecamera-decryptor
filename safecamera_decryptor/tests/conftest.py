from binascii import a2b_hex as unhex
import pytest

from safecamera_decryptor.decrypt import CipherParams, _Provider


class DummyProvider(_Provider):
    def __init__(self, initialization_vector, salt, content):
        """
        :param initialization_vector: the initialization vector as bytes
        :param salt: the salt as bytes
        :param content: the content as bytes
        """
        self.initialization_vector = initialization_vector
        self.salt = salt
        self.content = content

    def get_params(self):
        """Extract cipher parameters from the provider source."""
        return CipherParams(iv=self.initialization_vector, salt=self.salt)

    def read(self):
        """Return a generator which reads data from the provider source."""
        yield self.content


@pytest.fixture
def test_dot_png():
    return DummyProvider(
        initialization_vector=unhex('E654CB613B44DD258E5EA144D6094290'),
        salt=unhex(
            'F3174E38BB23A600CAEF2886F3A6C8CFCA71E608086006FC136E1A595ACB968C'
        ),
        content=unhex('2F12E2BE8AB4A31759D065A44DDD5496'),
    )
