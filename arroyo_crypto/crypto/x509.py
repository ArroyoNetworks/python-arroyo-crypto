# --------------------------------------------------------------------------- #


import logging

from abc import ABCMeta, abstractmethod

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from arroyo.crypto import PublicKey
from arroyo.utils import file_to_bytes, bytes_to_file

from . import EncodingType


# --------------------------------------------------------------------------- #


__all__ = ["x509Cert", "x509CertSignReq"]

LOG = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #


class x509Base(metaclass=ABCMeta):
    """
    High-level x509 Object Abstraction Base Class.
    """

    # Implementation Variables:
    #   _x509_obj:  The underlying x509 object from Cryptography
    #   __encoding: The underlying variable for the encoding getter/setter

    @classmethod
    def from_file(cls, path: str, **kwargs) -> "x509Base":
        """
        Create a new X509 Object from a given file.

        :param path: The path of the key file to load.
        :param kwargs: Additional key-word arguments to pass to the x509
         objects's init method.

        :return: A new ``BaseX509`` subclass representing the loaded
         file.

        :raises FileNotFoundError: If the given key file could not be found.
        """
        return cls(file_to_bytes(path), **kwargs)

    def __init__(self, x509_obj):
        """
        Creates a new instance of a ``x509Base`` subclass.
        """

        self.__encoding = None
        self._x509_obj = x509_obj

    def __bytes__(self):
        return self.to_bytes()

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        this_bytes = self.to_bytes(encoding=EncodingType.DER)
        other_bytes = other.to_bytes(encoding=EncodingType.DER)

        return this_bytes == other_bytes

    @property
    def encoding(self) -> EncodingType:
        """
        Returns the certificate serialization encoding.
        """
        return self.__encoding or EncodingType.DER

    @encoding.setter
    def encoding(self, value: EncodingType) -> None:
        """
        Sets the certificate serialization encoding.
        """
        try:
            value = EncodingType(value)
        except ValueError:
            raise ValueError("Encoding must be a type of EncodingType")
        self.__encoding = value

    @abstractmethod
    def to_bytes(self, *, encoding: EncodingType) -> bytes:
        """
        Returns the x509 object as bytes.
        """
        ...                                                   # pragma: nocover

    def to_file(self, path: str, **kwargs) -> bytes:
        """
        Writes the x509 object to a file.

        :param path: The path at which to write the new x509 object file.
        :param kwargs: Additional keyword arguments to pass into the object's
         `to_bytes` method.
        """
        bytes_to_file(
            path, self.to_bytes(**kwargs)
        )


class x509Cert(x509Base):
    """
    High level abstraction for X509 Certificates.

    This class is used to hide implementation level details for how
    X509 certificates are actually handled.
    """

    def __init__(self, data: bytes):
        """
        Creates a new Cert object from the given bytes.

        Changing the produced object will NOT change the underlying
        bytes. The new object must first be exported.

        :param data: The bytes of the certificate to load.

        :return: A new ``Cert`` representing the loaded certificate.

        :raises TypeError: If the value for ``data`` cannot be treated
         as bytes.
        :raises ValueError: If the given value for ``data`` cannot be properly
         decoded
        """
        if isinstance(data, str):
            data = data.encode()

        if not isinstance(data, bytes):
            raise TypeError("Value of 'data' must be bytes")

        args = (data, default_backend())
        # (1)   Try loading as DER
        try:
            super().__init__(x509_obj=x509.load_der_x509_certificate(*args))
            self.encoding = EncodingType.DER
            return
        except ValueError:
            pass

        # (2)   Try loading as PEM
        try:
            super().__init__(x509_obj=x509.load_pem_x509_certificate(*args))
            self.encoding = EncodingType.PEM
            return
        except ValueError:
            pass

        # Could not load - bytes not in suitable format.
        raise ValueError("Could not find a suitable encoding for 'data' "
                         "bytes, the data may not be a valid X509 certificate")

    def __contains__(self, item):
        return self.public_key == item

    @property
    def public_key(self) -> PublicKey:
        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
        # Use the SubjectPublicKeyInfo format since it can be used on all
        # key types.
        fmt = serialization.PublicFormat.SubjectPublicKeyInfo
        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
        k = self._x509_obj.public_key()
        data = k.public_bytes(self.encoding, fmt)
        return PublicKey(data=data)

    def to_bytes(self, *, encoding: EncodingType = None) -> bytes:
        """
        Returns the certificate as bytes.

        By default, the value of the ``encoding`` instance attribute is used
        to determine the byte serialization encoding. This behavior can be
        overridden by providing an explicit `encoding` value.

        :param encoding: Override the object's encoding before converting to
         bytes.
        :return: The public bytes of the x509 certificate.
        """
        encoding = encoding or self.encoding
        return self._x509_obj.public_bytes(encoding)


class x509CertSignReq(x509Base):
    """
    High-level abstraction class for x509 Certificate Signing Requests (CSRs).
    """

    def __init__(self, data: bytes):
        """
        Creates a new ``x509CertSignReq object from the given bytes.

        Changing the produced object will NOT change the underlying
        bytes. The new object must first be exported.

        :param data: The bytes of the CSR to load.

        :return: A new ``x509CertSignReq`` representing the loaded CSR.

        :raises TypeError: If the value for ``data`` cannot be treated
         as bytes.
        :raises ValueError: If the given value for ``data`` cannot be properly
         decoded
        """
        if isinstance(data, str):
            data = data.encode()

        if not isinstance(data, bytes):
            raise TypeError("Value of 'data' must be bytes")

        args = (data, default_backend())
        # (1)   Try loading as DER
        try:
            super().__init__(x509_obj=x509.load_der_x509_csr(*args))
            self.encoding = EncodingType.DER
            return
        except ValueError:
            pass

        # (2)   Try loading as PEM
        try:
            super().__init__(x509_obj=x509.load_pem_x509_csr(*args))
            self.encoding = EncodingType.PEM
            return
        except ValueError:
            pass

        # Could not load - bytes not in suitable format.
        raise ValueError("Could not find a suitable encoding for 'data' "
                         "bytes, the data may not be a valid X509 CSR")

    def to_bytes(self, *, encoding: EncodingType) -> bytes:
        """
        Returns the CSR as bytes.

        By default, the value of the ``encoding`` instance attribute is used
        to determine the byte serialization encoding. This behavior can be
        overridden by providing an explicit `encoding` value.

        :param encoding: Override the object's encoding before converting to
         bytes.
        :return: The bytes of the x509 signing request encoded with the given
         encoding.
        """
        encoding = encoding or self.encoding
        return self._x509_obj.public_bytes(encoding)
