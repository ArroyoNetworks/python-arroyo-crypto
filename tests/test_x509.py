# --------------------------------------------------------------------------- #


import os
import filecmp

from arroyo import utils
from arroyo.crypto import PublicKey, PrivateKey

import pytest

from .test_asymmetric import get_public_key_filename


# --------------------------------------------------------------------------- #

# x509 Tests

from arroyo_crypto.crypto import EncodingType, KeyAlgorithmType
from arroyo_crypto.crypto import x509


# --------------------------------------------------------------------------- #


HERE = os.path.dirname(__file__)


# --------------------------------------------------------------------------- #


def get_cert_filename(encoding):

    if not isinstance(encoding, str):
        encoding = encoding.value
    encoding = encoding.lower()

    csr_name = "{}_cert".format(encoding)
    return os.path.join(HERE, "certs", csr_name)


def get_cert_bytes(encoding):
    return utils.file_to_bytes(get_cert_filename(encoding))


def get_csr_filename(encoding):

    if not isinstance(encoding, str):
        encoding = encoding.value
    encoding = encoding.lower()

    csr_name = "{}_csr".format(encoding)
    return os.path.join(HERE, "certs", csr_name)


def get_csr_bytes(encoding):
    return utils.file_to_bytes(get_csr_filename(encoding))


# --------------------------------------------------------------------------- #


@pytest.fixture(scope="session",
                params=[e for e in EncodingType if e != EncodingType.OpenSSH])
def encoding(request):
    return request.param


@pytest.fixture(scope="session")
def der_cert():
    return x509.x509Cert(data=get_cert_bytes(EncodingType.DER))


@pytest.fixture(scope="session")
def pem_cert():
    return x509.x509Cert(data=get_cert_bytes(EncodingType.PEM))


@pytest.fixture(scope="session")
def der_csr():
    return x509.x509CertSignReq(data=get_csr_bytes(EncodingType.DER))


@pytest.fixture(scope="session")
def pem_csr():
    return x509.x509CertSignReq(data=get_csr_bytes(EncodingType.PEM))


# --------------------------------------------------------------------------- #

# x509Cert Tests

def test_load_cert_files(encoding):

    cert_file = get_cert_filename(encoding)
    cert = x509.x509Cert.from_file(cert_file)

    assert isinstance(cert, x509.x509Cert)
    assert cert.encoding == encoding


def test_load_invalid_cert_file(nonempty_file):

    with pytest.raises(ValueError):
        x509.x509Cert.from_file(nonempty_file)


def test_load_nonexisting_cert_file(nonexisting_file):

    with pytest.raises(FileNotFoundError):
        x509.x509Cert.from_file(nonexisting_file)


def test_cert_to_file(encoding, empty_file):

    cert_file = get_cert_filename(encoding)
    cert = x509.x509Cert(data=get_cert_bytes(encoding))

    cert.to_file(empty_file)

    assert filecmp.cmp(cert_file, empty_file)


def test_cert_eq_method(der_cert, pem_cert):

    assert der_cert == pem_cert


def test_cert_eq_method_invalid_other(der_cert):

    assert not der_cert == 12345


def test_cert_ne_method(der_cert, pem_cert):

    assert not der_cert != pem_cert


def test_cert_bytes_method_der_encoding():

    der_bytes = get_cert_bytes(EncodingType.DER)
    pem_bytes = get_cert_bytes(EncodingType.PEM)

    cert = x509.x509Cert(data=der_bytes)

    assert bytes(cert) == cert.to_bytes()
    assert bytes(cert) == der_bytes

    assert cert.to_bytes(encoding=EncodingType.PEM) == pem_bytes


def test_cert_bytes_method_pem_encoding():

    der_bytes = get_cert_bytes(EncodingType.DER)
    pem_bytes = get_cert_bytes(EncodingType.PEM)

    cert = x509.x509Cert(data=pem_bytes)

    assert bytes(cert) == cert.to_bytes()
    assert bytes(cert) == pem_bytes

    assert cert.to_bytes(encoding=EncodingType.DER) == der_bytes


def test_cert_bytes_method_switch_encoding():

    der_bytes = get_cert_bytes(EncodingType.DER)
    pem_bytes = get_cert_bytes(EncodingType.PEM)

    cert = x509.x509Cert(data=der_bytes)
    cert.encoding = EncodingType.PEM

    assert bytes(cert) == pem_bytes


def test_cert_contains_methods():

    key_file = get_public_key_filename(KeyAlgorithmType.RSA, EncodingType.DER)
    key = PublicKey(data=utils.file_to_bytes(key_file))

    cert = x509.x509Cert(data=get_cert_bytes(EncodingType.DER))

    assert key not in cert


def test_cert_set_invalid_encoding(der_cert):

    with pytest.raises(ValueError):
        der_cert.encoding = None


def test_cert_invalid_data_type():

    with pytest.raises(TypeError):
        x509.x509Cert(data=12345)


def test_cert_invalid_data_value():

    with pytest.raises(ValueError):
        x509.x509Cert(data=b'\x00\x01\x02')


def test_cert_public_key(encoding):

    cert = x509.x509Cert(data=get_cert_bytes(encoding))
    key = cert.public_key

    assert isinstance(key, PublicKey)
    assert key in cert


# --------------------------------------------------------------------------- #

# x509CertSignReq Tests

def test_load_csr_files(encoding):

    csr_file = get_csr_filename(encoding)
    csr = x509.x509CertSignReq.from_file(csr_file)

    assert isinstance(csr, x509.x509CertSignReq)
    assert csr.encoding == encoding


def test_load_invalid_csr_file(nonempty_file):

    with pytest.raises(ValueError):
        x509.x509CertSignReq.from_file(nonempty_file)


def test_load_nonexisting_csr_file(nonexisting_file):

    with pytest.raises(FileNotFoundError):
        x509.x509CertSignReq.from_file(nonexisting_file)


def test_csr_to_file(encoding, empty_file):

    csr_file = get_csr_filename(encoding)
    csr = x509.x509CertSignReq(data=get_csr_bytes(encoding))

    csr.to_file(empty_file)

    assert filecmp.cmp(csr_file, empty_file)


def test_csr_eq_method(der_csr, pem_csr):

    assert der_csr == pem_csr


def test_csr_eq_method_invalid_other(der_csr):

    assert not der_csr == 12345


def test_csr_ne_method(der_csr, pem_csr):

    assert not der_csr != pem_csr


def test_csr_bytes_method_der_encoding():

    der_bytes = get_csr_bytes(EncodingType.DER)
    pem_bytes = get_csr_bytes(EncodingType.PEM)

    csr = x509.x509CertSignReq(data=der_bytes)

    assert bytes(csr) == csr.to_bytes()
    assert bytes(csr) == der_bytes

    assert csr.to_bytes(encoding=EncodingType.PEM) == pem_bytes


def test_csr_bytes_method_pem_encoding():

    der_bytes = get_csr_bytes(EncodingType.DER)
    pem_bytes = get_csr_bytes(EncodingType.PEM)

    csr = x509.x509CertSignReq(data=pem_bytes)

    assert bytes(csr) == csr.to_bytes()
    assert bytes(csr) == pem_bytes

    assert csr.to_bytes(encoding=EncodingType.DER) == der_bytes


def test_csr_bytes_method_switch_encoding():

    der_bytes = get_csr_bytes(EncodingType.DER)
    pem_bytes = get_csr_bytes(EncodingType.PEM)

    csr = x509.x509CertSignReq(data=der_bytes)
    csr.encoding = EncodingType.PEM

    assert bytes(csr) == pem_bytes


def test_csr_set_invalid_encoding(der_csr):

    with pytest.raises(ValueError):
        der_csr.encoding = None


def test_csr_invalid_data_type():

    with pytest.raises(TypeError):
        x509.x509CertSignReq(data=12345)


def test_csr_invalid_data_value():

    with pytest.raises(ValueError):
        x509.x509CertSignReq(data=b'\x00\x01\x02')


def test_generate_no_dn_single_alt_dns_name(key_algorithm):

    key = PrivateKey.generate(key_algorithm)

    csr = x509.x509CertSignReq.generate(
        key,
        "seglberg.arroyo.io"
    )


def test_generate_no_dn_multiple_alt_dns_name(key_algorithm):

    key = PrivateKey.generate(key_algorithm)

    csr = x509.x509CertSignReq.generate(
        key,
        ["seglberg.arroyo.io", "test.arroyo.io"]
    )


def test_generate_malformed_alt_dns_name():

    key = PrivateKey.generate(KeyAlgorithmType.DSA)

    with pytest.raises(ValueError):
        csr = x509.x509CertSignReq.generate(
            key,
            "`this is not valid`"
        )


def test_generate_empty_list_alt_dns_name():

    key = PrivateKey.generate(KeyAlgorithmType.DSA)

    with pytest.raises(ValueError):
        csr = x509.x509CertSignReq.generate(
            key,
            []
        )


def test_generate_full_dn_single_alt_dns_name(key_algorithm):

    key = PrivateKey.generate(key_algorithm)

    csr = x509.x509CertSignReq.generate(
        key,
        "seglberg.arroyo.io",
        CN="*.seglberg.arroyo.io",
        O="Arroyo Networks, LLC",
        OU="Elite Squad Delta Force 7",
        L="Hell",
        ST="Michigan",
        C="US"
    )


def test_generate_full_dn_multi_alt_dns_name(key_algorithm):

    key = PrivateKey.generate(key_algorithm)

    csr = x509.x509CertSignReq.generate(
        key,
        ["seglberg.arroyo.io", "test.arroyo.io"],
        CN="*.seglberg.arroyo.io",
        O="Arroyo Networks, LLC",
        OU="Elite Squad Delta Force 7",
        L="Hell",
        ST="Michigan",
        C="US"
    )


def test_generate_invalid_dn_value():

    key = PrivateKey.generate(KeyAlgorithmType.DSA)

    with pytest.raises(ValueError):
        csr = x509.x509CertSignReq.generate(
            key,
            "seglberg.arroyo.io",
            C="Not A Valid Country :)"
        )
