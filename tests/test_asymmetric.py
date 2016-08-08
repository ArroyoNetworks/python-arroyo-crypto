# --------------------------------------------------------------------------- #


import os
import filecmp

from arroyo import utils

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


class FakeTestKey(asymmetric.AsymmetricKey):
    def __eq__(self, other):
        pass

    def to_bytes(self, *, encoding: EncodingType, fmt: str):
        pass

    def to_jwk(self):
        return b'\x00\x01'


# --------------------------------------------------------------------------- #


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


def test_load_encrypted_private_key_files_str_pass(key_algorithm,
                                                   private_key_encoding):

    key_file = get_private_key_filename(key_algorithm, private_key_encoding,
                                        encrypted=True)
    key = asymmetric.PrivateKey.from_file(key_file, password=PASSWORD.decode())

    assert isinstance(key, asymmetric.PrivateKey)

    assert key.algorithm == key_algorithm
    assert key.encoding == private_key_encoding


def test_load_encrypted_private_key_files_inv_pass_type(key_algorithm,
                                                        private_key_encoding):

    key_file = get_private_key_filename(key_algorithm, private_key_encoding,
                                        encrypted=True)
    with pytest.raises(TypeError):
        asymmetric.PrivateKey.from_file(key_file, password=12345)


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
    assert key1 != 12345


def test_public_key_equality():

    key_file = get_public_key_filename(KeyAlgorithmType.RSA, EncodingType.PEM)
    pub_key = asymmetric.PublicKey.from_file(key_file)

    key_file = get_private_key_filename(KeyAlgorithmType.RSA, EncodingType.PEM)
    priv_key = asymmetric.PrivateKey.from_file(key_file)

    assert priv_key.public_key is not pub_key
    assert priv_key.public_key == pub_key
    assert not priv_key.public_key != pub_key
    assert pub_key != 12345

    # Test the __contains__ Operator
    assert pub_key in priv_key


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


def test_rsa_private_key_to_jwk():

    key_file = get_private_key_filename(KeyAlgorithmType.RSA, EncodingType.PEM)
    key = asymmetric.PrivateKey.from_file(key_file)

    jwk = key.to_jwk()

    assert jwk['kty'] == 'RSA'

    assert 'n' in jwk
    assert 'e' in jwk
    assert 'd' in jwk
    assert 'p' in jwk
    assert 'q' in jwk
    assert 'dp' in jwk
    assert 'dq' in jwk
    assert 'qi' in jwk


def test_dsa_private_key_to_jwk():
    """Test to ensure that attempting to convert a DSA key to a JWK results
    in an exception thrown, since DSA keys cannot be represented as JWKs."""

    key_file = get_private_key_filename(KeyAlgorithmType.DSA, EncodingType.PEM)
    key = asymmetric.PrivateKey.from_file(key_file)

    with pytest.raises(TypeError):
        key.to_jwk()


def test_ecdsa_private_key_to_jwk():

    key_file = get_private_key_filename(KeyAlgorithmType.ECDSA,
                                        EncodingType.PEM)
    key = asymmetric.PrivateKey.from_file(key_file)

    with pytest.raises(NotImplementedError):
        key.to_jwk()


def test_rsa_private_key_jwk_fingerprint():

    key_file = get_private_key_filename(KeyAlgorithmType.RSA, EncodingType.PEM)
    key = asymmetric.PrivateKey.from_file(key_file)

    jwk_fingerprint = key.jwk_fingerprint

    assert isinstance(jwk_fingerprint, str)

    # Ensure the result can be decoded as JOSE base64 and appears to be a
    # SHA256 result
    decoded = utils.jose_b64decode(jwk_fingerprint)
    assert len(decoded) * 8 == 256


def test_invalid_key_type():

    with pytest.raises(TypeError):
        FakeTestKey(key=25)


def test_invalid_to_jwk():

    key_file = get_private_key_filename(KeyAlgorithmType.RSA, EncodingType.PEM)
    key = asymmetric.PrivateKey.from_file(key_file)

    new_key = FakeTestKey(key=key._key)
    with pytest.raises(TypeError):
        new_key.jwk_fingerprint


def test_direct_public_key_creation_as_str(key_algorithm):

    key_file = get_public_key_filename(key_algorithm, EncodingType.PEM)
    with open(key_file, 'r') as f:
        key_data = f.read()

    asymmetric.PublicKey(data=key_data)


def test_direct_public_key_invalid_data():

    with pytest.raises(TypeError):
        asymmetric.PublicKey(data=54321)


def test_direct_private_key_creation_as_str(key_algorithm):

    key_file = get_private_key_filename(key_algorithm, EncodingType.PEM)
    with open(key_file, 'r') as f:
        key_data = f.read()

    asymmetric.PrivateKey(data=key_data)


def test_direct_private_key_invalid_data():

    with pytest.raises(TypeError):
        asymmetric.PrivateKey(data=54321)


def test_invalid_public_key_file(nonempty_file):

    with pytest.raises(ValueError):
        asymmetric.PublicKey.from_file(nonempty_file)


def test_invalid_private_key_file(nonempty_file):

    with pytest.raises(ValueError):
        asymmetric.PrivateKey.from_file(nonempty_file)


# --------------------------------------------------------------------------- #

# Key Generation Tests


def test_strong_key_generation(recwarn, key_algorithm):

    key = asymmetric.PrivateKey.generate(key_algorithm)

    # Ensure that the default parameters generate a "strong" key
    # (thus no warnings were raised)
    assert len(recwarn) == 0
    assert key.algorithm is key_algorithm


def test_weak_rsa_key_generation(recwarn):

    key = asymmetric.PrivateKey.generate(KeyAlgorithmType.RSA, size=1024)

    # Ensure that a warning was raised since the key size will generate a
    # "weak" key
    assert len(recwarn) > 0
    assert key.algorithm is KeyAlgorithmType.RSA


def test_weak_dsa_key_generation(recwarn):

    key = asymmetric.PrivateKey.generate(KeyAlgorithmType.DSA, size=1024)

    # Ensure that a warning was raised since the key size will generate a
    # "weak" key
    assert len(recwarn) > 0
    assert key.algorithm is KeyAlgorithmType.DSA


def test_invalid_ecdsa_curve_size():

    with pytest.warns(UserWarning) as record:
        asymmetric.PrivateKey.generate(KeyAlgorithmType.ECDSA, size=1)

    # Ensure that a warning was raised about the key size being too small
    # and that it was rounded up.
    assert len(record) == 1
    assert "Rounding up" in str(record[0].message)


def test_too_large_ecdsa_curve_size():

    with pytest.warns(UserWarning) as record:
        asymmetric.PrivateKey.generate(KeyAlgorithmType.ECDSA, size=9999999999)

    # Ensure that a warning was raised about the key size being too small
    # and that it was rounded up.
    assert len(record) == 1
    assert "Rounding down" in str(record[0].message)

