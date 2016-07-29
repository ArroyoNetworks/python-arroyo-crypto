

import os
import tempfile
import filecmp

import pytest


# --------------------------------------------------------------------------- #

# Asymmetric Key Tests

from arroyo_crypto.crypto import KeyAlgorithmType, EncodingType
from arroyo_crypto.crypto import asymmetric


# --------------------------------------------------------------------------- #


PASSWORD = b'password'
HERE = os.path.dirname(__file__)


# --------------------------------------------------------------------------- #


def get_public_key_filename(key_type, key_encoding):

    if not isinstance(key_type, str):
        key_type = key_type.value
    key_type = key_type.lower()

    if not isinstance(key_encoding, str):
        key_encoding = key_encoding.value
    key_encoding = key_encoding.lower()

    key_name = "{}_public_{}.key".format(key_type, key_encoding)
    return os.path.join(HERE, "keys", key_name)


def get_private_key_filename(key_type, key_encoding, encrypted=False):

    if not isinstance(key_type, str):
        key_type = key_type.value
    key_type = key_type.lower()

    if not isinstance(key_encoding, str):
        key_encoding = key_encoding.value
    key_encoding = key_encoding.lower()

    if encrypted:
        key_name = "{}_private_{}_encrypted.key".format(key_type, key_encoding)
    else:
        key_name = "{}_private_{}.key".format(key_type, key_encoding)

    return os.path.join(HERE, "keys", key_name)


# --------------------------------------------------------------------------- #


@pytest.fixture
def empty_file(request):
    """
    Returns the path of an empty temp. file that will be automatically be
    deleted when the test ends.
    """

    tmp = tempfile.NamedTemporaryFile(delete=False)

    def finalizer():
        os.remove(tmp.name)
    request.addfinalizer(finalizer)

    return tmp.name


@pytest.fixture(scope="session", params=KeyAlgorithmType)
def key_algorithm(request):
    return request.param


@pytest.fixture(scope="session", params=EncodingType)
def public_key_encoding(request):
    return request.param


@pytest.fixture(scope="session",
                params=[e for e in EncodingType if e != EncodingType.OpenSSH])
def private_key_encoding(request):
    return request.param


# --------------------------------------------------------------------------- #


def test_load_public_key_files(key_algorithm, public_key_encoding):

    key_file = get_public_key_filename(key_algorithm, public_key_encoding)
    key = asymmetric.PublicKey.from_file(key_file)

    assert isinstance(key, asymmetric.PublicKey)

    assert key.algorithm == key_algorithm
    assert key.encoding == public_key_encoding


def test_load_private_key_files(key_algorithm, private_key_encoding):

    key_file = get_private_key_filename(key_algorithm, private_key_encoding)
    key = asymmetric.PrivateKey.from_file(key_file)

    assert isinstance(key, asymmetric.PrivateKey)

    assert key.algorithm == key_algorithm
    assert key.encoding == private_key_encoding


def test_load_encrypted_private_key_files(key_algorithm, private_key_encoding):

    key_file = get_private_key_filename(key_algorithm, private_key_encoding,
                                        encrypted=True)
    key = asymmetric.PrivateKey.from_file(key_file, password=PASSWORD)

    assert isinstance(key, asymmetric.PrivateKey)

    assert key.algorithm == key_algorithm
    assert key.encoding == private_key_encoding


def test_unsupported_key_algorithm():

    class FakeSubclass(asymmetric.AsymmetricKey):

        def to_bytes(self, *, encoding: EncodingType, fmt: str) -> bytes:
            pass

        def __eq__(self, other):
            return True

    with pytest.raises(TypeError):
        FakeSubclass(key=None)


def test_private_key_bytes():

    key_file = get_private_key_filename(KeyAlgorithmType.RSA, EncodingType.PEM)
    key = asymmetric.PrivateKey.from_file(key_file)

    assert isinstance(bytes(key), bytes)
    assert bytes(key) == key.to_bytes()


def test_public_key_bytes():

    key_file = get_public_key_filename(KeyAlgorithmType.RSA, EncodingType.PEM)
    key = asymmetric.PublicKey.from_file(key_file)

    assert isinstance(bytes(key), bytes)
    assert bytes(key) == key.to_bytes()


def test_private_key_size():

    key_file = get_private_key_filename(KeyAlgorithmType.RSA, EncodingType.PEM)
    key = asymmetric.PrivateKey.from_file(key_file)

    assert isinstance(len(key), int)
    assert len(key) == key.size


def test_public_key_size():

    key_file = get_public_key_filename(KeyAlgorithmType.RSA, EncodingType.PEM)
    key = asymmetric.PublicKey.from_file(key_file)

    assert isinstance(len(key), int)
    assert len(key) == key.size


def test_private_key_equality():

    key_file = get_private_key_filename(KeyAlgorithmType.RSA, EncodingType.PEM)

    key1 = asymmetric.PrivateKey.from_file(key_file)
    key2 = asymmetric.PrivateKey.from_file(key_file)

    assert key1 is not key2
    assert key1 == key2
    assert not key1 != key2


def test_public_key_equality():

    key_file = get_public_key_filename(KeyAlgorithmType.RSA, EncodingType.PEM)
    pub_key = asymmetric.PublicKey.from_file(key_file)

    key_file = get_private_key_filename(KeyAlgorithmType.RSA, EncodingType.PEM)
    priv_key = asymmetric.PrivateKey.from_file(key_file)

    assert priv_key.public_key is not pub_key
    assert priv_key.public_key == pub_key
    assert not priv_key.public_key != pub_key


def test_size_in_repr(key_algorithm):

    key_file = get_private_key_filename(key_algorithm, EncodingType.PEM)
    key = asymmetric.PrivateKey.from_file(key_file)

    assert str(key.size) in repr(key)


def test_algorithm_in_repr(key_algorithm):

    key_file = get_private_key_filename(key_algorithm, EncodingType.PEM)
    key = asymmetric.PrivateKey.from_file(key_file)

    assert str(key_algorithm.value) in repr(key)


def test_set_invalid_encoding():

    key_file = get_private_key_filename(KeyAlgorithmType.RSA, EncodingType.PEM)
    key = asymmetric.PrivateKey.from_file(key_file)

    with pytest.raises(ValueError):
        key.encoding = b'NotValid'


def test_private_key_to_file(key_algorithm, private_key_encoding, empty_file):

    key_file = get_private_key_filename(key_algorithm, private_key_encoding)
    key = asymmetric.PrivateKey.from_file(key_file)

    key.to_file(empty_file)

    assert filecmp.cmp(key_file, empty_file)


def test_private_key_to_file_encrypted(key_algorithm, private_key_encoding,
                                       empty_file):

    key_file = get_private_key_filename(key_algorithm, private_key_encoding)
    key1 = asymmetric.PrivateKey.from_file(key_file)

    key1.to_file(empty_file, password=PASSWORD)
    key2 = asymmetric.PrivateKey.from_file(empty_file, password=PASSWORD)

    assert key1 == key2


@pytest.mark.xfail
def test_public_key_to_file(key_algorithm, public_key_encoding, empty_file):

    # XXX: Currently this fails because we are not using sane defaults
    # when writing out Public Keys, specifically ECDSA keys.

    key_file = get_public_key_filename(key_algorithm, public_key_encoding)
    key = asymmetric.PublicKey.from_file(key_file)

    key.to_file(empty_file)

    assert filecmp.cmp(key_file, empty_file)

