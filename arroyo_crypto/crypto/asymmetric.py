# --------------------------------------------------------------------------- #


import logging
import warnings
import json
from datetime import datetime
from enum import Enum
from math import ceil

from abc import ABCMeta, abstractmethod

from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

from arroyo.utils import (
    file_to_bytes, bytes_to_file, jose_b64encode
)

from . import EncodingType


# --------------------------------------------------------------------------- #

# Typing

from typing import Union

_STR_TYPE = Union[bytes, str]


# --------------------------------------------------------------------------- #


__all__ = ["KeyAlgorithmType", "PublicKey", "PrivateKey"]

LOG = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #


class KeyAlgorithmType(str, Enum):
    # EdDSA (ED25519) is current not supported
    RSA = "RSA"
    DSA = "DSA"
    ECDSA = "ECDSA"


_KEY_MIN_SIZES = {
    KeyAlgorithmType.RSA: 2048 if datetime.now().year < 2020 else 4096,
    KeyAlgorithmType.DSA: 2048 if datetime.now().year < 2030 else 3072,
    KeyAlgorithmType.ECDSA: 224,
}


_P_CURVES = {
    192: ec.SECP192R1,      # NIST P-192
    224: ec.SECP224R1,      # NIST P-224
    256: ec.SECP256R1,      # NIST P-256
    384: ec.SECP384R1,      # NIST P-384
    521: ec.SECP521R1       # NIST P-521
}


def _type_from_instance(instance) -> KeyAlgorithmType:
    """
    Returns the corresponding AlgorithmType for a given class.

    :param instance: The class instance to lookup.

    :return: The AlgorithmType corresponding to the given class.

    :raises TypeError: If the given class is not valid for producing an
     ``AlgorithmType``.
    """
    if isinstance(instance, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        return KeyAlgorithmType.RSA
    if isinstance(instance, (dsa.DSAPublicKey, dsa.DSAPrivateKey)):
        return KeyAlgorithmType.DSA
    if isinstance(instance, (ec.EllipticCurvePublicKey,
                             ec.EllipticCurvePrivateKey)):
        return KeyAlgorithmType.ECDSA

    raise TypeError("Could not determine AlgorithmType for given class for "
                    "{}".format(instance.__class__))


def _prepare_jwk_num(num):
    # NOTE: --
    # Some implementations will but a leading null byte in front of key
    # numbers to remove the ambiguity with their sign, however JOSE/JWK
    # requires that there be no null bytes.
    #
    # While this does not affect
    # signing operations, it will cause the fingerprint/thumbprint to
    # be wrong.

    if isinstance(num, int):
        num = num.to_bytes(ceil(num.bit_length() / 8), "big")

    if isinstance(num, bytes):
        num = jose_b64encode(num)

    return num


# --------------------------------------------------------------------------- #


class AsymmetricKey(metaclass=ABCMeta):
    """
    High level abstraction for asymmetric keys.

    This class is an actual python ABCMeta class, and is used to derive
    two main subclasses: ``PrivateKey`` and ``PublicKey``.
    """

    # Implementation Variables:
    #   __encoding:     The underlying variable for the encoding getter/setter
    #   __algorithm:    The underlying variable for the algorithm getter
    #   _key:           The underlying cryptography key instance.

    @classmethod
    def from_file(cls, path: str, **kwargs) -> "AsymmetricKey":
        """
        Create a new AsymmetricKey from a given file.

        :param path: The path of the key file to load.
        :param kwargs: Additional key-word arguments to pass to the key's
         init method, such as `password` for private keys.

        :return: A new ``AsymmetricKey`` subclass representing the loaded
         file.

        :raises FileNotFoundError: If the given key file could not be found.
        """
        return cls(file_to_bytes(path), **kwargs)

    def __init__(self, key):
        """
        Creates a new AsymmetricKey subclass from the given key.

        This class should never be instantiated directly for outside this
        library, and it's init method is not considered part of the public
        API and thus may change.

        See ``PrivateKey`` and ``PublicKey``.
        """
        self.__encoding = None
        try:
            self.__algorithm = KeyAlgorithmType(_type_from_instance(key))
        except TypeError:
            raise TypeError("Unsupported Key Algorithm or Type")
        self._key = key

    def __bytes__(self):
        return self.to_bytes()

    def __len__(self):
        return self.size

    @abstractmethod
    def __eq__(self, other):
        ...                                                   # pragma: nocover

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        name = str(self.__class__).strip('<').rstrip('>')
        alg = self.algorithm.value
        enc = self.encoding.value
        return '<{0}, {1}-{2}/{3}>'.format(name, alg, self.size, enc)

    @property
    def algorithm(self) -> KeyAlgorithmType:
        """
        Returns the key algorithm type.
        """
        return self.__algorithm

    @property
    def encoding(self) -> EncodingType:
        """
        Returns the key serialization encoding.
        """
        return self.__encoding or EncodingType.DER

    @encoding.setter
    def encoding(self, value: EncodingType) -> None:
        """
        Sets the key serialization encoding.
        """
        try:
            value = EncodingType(value)
        except ValueError:
            raise ValueError("Encoding must be a type of EncodingType")
        self.__encoding = value

    @property
    def jwk_fingerprint(self) -> str:
        try:
            serial_jwk = json.dumps(
                self.to_jwk(),
                sort_keys=True,
                separators=(',', ':')
            )
        except TypeError:
            raise

        jwk_hash = hashes.Hash(hashes.SHA256(), default_backend())
        jwk_hash.update(serial_jwk.encode())

        return jose_b64encode(jwk_hash.finalize())

    @property
    def size(self) -> int:
        """
        Returns the key size.
        """
        if self.algorithm is KeyAlgorithmType.ECDSA:
            return self._key.curve.key_size
        return self._key.key_size

    @abstractmethod
    def to_bytes(self, *, encoding: EncodingType, fmt: str) -> bytes:
        """
        Returns the key as bytes.
        """
        ...                                                   # pragma: nocover

    def to_file(self, path: str, **kwargs) -> bytes:
        """
        Writes the key to a file.

        :param path: The path at which to write the new key file.
        :param kwargs: Additional keyword arguments to pass into the key's
         `to_bytes` method.
        """
        bytes_to_file(
            path, self.to_bytes(**kwargs)
        )

    @abstractmethod
    def to_jwk(self) -> dict:
        """
        Convert the key to JWK (JSON Web Key) format.

        :return: A dictionary representation of this key in JWK format.
        """
        if self.algorithm is KeyAlgorithmType.DSA:
            raise TypeError("DSA keys cannot be converted to JWK, "
                            "see RFC 7517")

        return dict(kty=self.algorithm.upper())


class PublicKey(AsymmetricKey):
    """
    High level class for representing and interacting with public asymmetric
    keys.
    """

    def __init__(self, data: _STR_TYPE):
        """
        Creates a new ``PublicKey`` representing the given public bytes.

        Changing the produced object will NOT change the underlying
        bytes. The new object must first be exported.

        :param data: The public key byte-data.
        :raises ValueError: If the given key data bytes cannot be loaded,
         and thus may not represent a valid private key.
        """

        if isinstance(data, str):
            data = data.encode()

        if not isinstance(data, bytes):
            raise TypeError("Value of 'data' must be bytes")

        args = (data, default_backend())
        # (1)   Try loading public key as DER
        try:
            super().__init__(key=serialization.load_der_public_key(*args))
            self.encoding = EncodingType.DER
            return
        except ValueError:
            pass

        # (2)   Try loading public key as PEM
        try:
            super().__init__(key=serialization.load_pem_public_key(*args))
            self.encoding = EncodingType.PEM
            return
        except ValueError:
            pass

        # (3)   Try loading public key as OpenSSH
        try:
            super().__init__(key=serialization.load_ssh_public_key(*args))
            self.encoding = EncodingType.OpenSSH
            return
        except (ValueError, serialization.UnsupportedAlgorithm):
            pass

        raise ValueError("Could not find a suitable encoding for 'data' "
                         "bytes, the data may not be a valid public key")

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        # Comparison is done with DER bytes.
        other_bytes = other.to_bytes(
            encoding=EncodingType.DER,
            fmt=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        this_bytes = self.to_bytes(
            encoding=EncodingType.DER,
            fmt=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return this_bytes == other_bytes

    def to_bytes(self, *, encoding: EncodingType = None,
                 fmt: str = None) -> bytes:
        """
        Returns the key as bytes.

        By default, the value of the ``encoding`` instance attribute is used
        to determine the byte serialization encoding. This behavior can be
        overridden by providing an explicit `encoding` value.

        By default, the format of the bytes is PKCS1 or OpenSSH for OpenSSH
        encoded keys.

        :param encoding: Keyword-only argument to override the object's
         encoding before converting to bytes.
        :param fmt: Keyword-only argument to set the byte format, by default
         PKCS1 is used.

        :return: The raw bytes of the public key.
        """
        encoding = encoding or self.encoding
        fmt = fmt or (
            serialization.PublicFormat.OpenSSH
            if encoding is EncodingType.OpenSSH
            else serialization.PublicFormat.PKCS1
        )
        return self._key.public_bytes(encoding, fmt)

    def to_jwk(self) -> dict:
        jwk = super().to_jwk()
        if self.algorithm is KeyAlgorithmType.RSA:
            jwk['n'] = _prepare_jwk_num(self._key.public_numbers().n)
            jwk['e'] = _prepare_jwk_num(self._key.public_numbers().e)
        else:
            raise NotImplementedError("Conversion to JWK not implemented"
                                      " for this type of key yet.")
        return jwk


class PrivateKey(AsymmetricKey):
    """
    High level class for representing and interacting with private asymmetric
    keys.
    """

    @classmethod
    def generate(cls, algorithm: KeyAlgorithmType, *,
                 size: int = None) -> "PrivateKey":
        """
        Generates a new private key using the given algorithm (key type).

        Safe defaults will automatically be used, and my change time to time.
        Some of the defaults can be overridden, such as size.

        Not all options are used for all algorithms, and may be ignored.

        :param algorithm: The type of key to generate.
        :param size: Keyword-only argument to override the default key size,
         if applicable for the given algorithm.

        :return: A new ``PrivateKey`` representing the newly generated key.

        :raises TypeError: If the given algorithm is an invalid AlgorithmType.
        :raises TypeError: If the given key size is not an integer.
        """
        algorithm = KeyAlgorithmType(algorithm)
        if size:
            size = int(size)
        size = size or _KEY_MIN_SIZES[algorithm]

        # RSA Key Generation
        if algorithm is KeyAlgorithmType.RSA:

            if size < _KEY_MIN_SIZES[KeyAlgorithmType.RSA]:
                warnings.warn("RSA Key Size '{}' Considered Weak".format(size))

            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=size,
                backend=default_backend()
            )

        # DSA Key Generation
        elif algorithm is KeyAlgorithmType.DSA:

            if size < _KEY_MIN_SIZES[KeyAlgorithmType.DSA]:
                warnings.warn("DSA Key Size '{}' Considered Weak".format(size))

            key = dsa.generate_private_key(
                key_size=size,
                backend=default_backend()
            )

        # ECDSA Key Generation
        else:  # algorithm is AlgorithmType.ECDSA:

            warning = "Invalid Curve Size '{}': Rounding up to {} bits"
            for curve_size in _P_CURVES:

                if size <= curve_size:
                    if size < curve_size:
                        warnings.warn(warning.format(size, curve_size))
                    curve = _P_CURVES[curve_size]
                    break

            # User specified too large of a key size
            else:

                max_size = list(_P_CURVES)[-1]
                warnings.warn("Invalid Curve Size '{}': Rounding down to {} "
                              "bits".format(size, max_size))
                curve = _P_CURVES[max_size]

            key = ec.generate_private_key(
                curve=curve,
                backend=default_backend()
            )

        # Serialize Key to Bytes
        key_bytes = key.private_bytes(
            EncodingType.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )

        return cls(data=key_bytes)

    def __init__(self, data: _STR_TYPE, password: _STR_TYPE = None):
        """
        Creates a new ``PrivateKey`` representing the given private bytes.

        :param data: The private key byte-data.
        :param password: The password, if required, to decrypt the given key
         data. Defaults to ``None``.

        :raises TypeError: If the key is encrypted, but no password was given.
        :raises TypeError: If a password is given, but the file is not
         encrypted.
        :raises ValueError: If the given key data bytes cannot be loaded,
         and thus may not represent a valid private key.
        """

        if isinstance(data, str):
            data = data.encode()

        if not isinstance(data, bytes):
            raise TypeError("Value of 'data' must be bytes")

        if isinstance(password, str):
            password = password.encode()

        if password and not isinstance(password, bytes):
            raise TypeError("Value of 'password' must be bytes")

        args = (data, password, default_backend())
        # (1)   Try loading public key as DER
        try:
            super().__init__(key=serialization.load_der_private_key(*args))
            self.encoding = EncodingType.DER
            return
        except ValueError:
            pass

        # (2)   Try loading public key as PEM
        try:
            super().__init__(key=serialization.load_pem_private_key(*args))
            self.encoding = EncodingType.PEM
            return
        except ValueError:
            pass

        raise ValueError("Could not find a suitable encoding for 'data' "
                         "bytes, the data may not be a valid private key")

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        # Comparison is done with DER bytes.
        other_bytes = other.to_bytes(
            encoding=EncodingType.DER,
            fmt=serialization.PrivateFormat.PKCS8
        )
        this_bytes = self.to_bytes(
            encoding=EncodingType.DER,
            fmt=serialization.PrivateFormat.PKCS8
        )
        return this_bytes == other_bytes

    def __contains__(self, item):
        return self.public_key == item

    @property
    def public_key(self) -> PublicKey:
        """
        Returns the public key corresponding to this private key.
        """
        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
        # Use the SubjectPublicKeyInfo format since it can be used on all
        # key types.
        fmt = serialization.PublicFormat.SubjectPublicKeyInfo
        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
        k = self._key.public_key()
        data = k.public_bytes(self.encoding, fmt)
        return PublicKey(data=data)

    def to_bytes(self, password: bytes = None, *,
                 encoding: EncodingType = None, fmt: str = None) -> bytes:
        """
        Returns the key as bytes.

        By default, the value of the ``encoding`` instance attribute is used
        to determine the byte serialization encoding. This behavior can be
        overridden by providing an explicit `encoding` value.

        By default, the format of the bytes is PKCS8.

        :param password: Optional password used to encrypt the key bytes.
        :param encoding: Keyword-only argument to override the object's
         encoding before converting to bytes.
        :param fmt: Keyword-only argument to set the byte format, by default
         PKCS8 is used.

        :return: The raw bytes of the private key.
        """
        if password is not None:
            password = serialization.BestAvailableEncryption(password)
        else:
            password = serialization.NoEncryption()
        encoding = encoding or self.encoding
        fmt = fmt or serialization.PrivateFormat.PKCS8
        return self._key.private_bytes(encoding, fmt, password)

    def to_jwk(self):
        jwk = self.public_key.to_jwk()

        if self.algorithm is KeyAlgorithmType.RSA:
            jwk['d'] = _prepare_jwk_num(self._key.private_numbers().d)
            jwk['p'] = _prepare_jwk_num(self._key.private_numbers().p)
            jwk['q'] = _prepare_jwk_num(self._key.private_numbers().q)
            jwk['dp'] = _prepare_jwk_num(self._key.private_numbers().dmp1)
            jwk['dq'] = _prepare_jwk_num(self._key.private_numbers().dmq1)
            jwk['qi'] = _prepare_jwk_num(self._key.private_numbers().iqmp)

        return jwk
