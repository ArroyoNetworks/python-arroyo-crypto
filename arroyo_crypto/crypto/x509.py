
import logging

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from arroyo.utils import file_to_bytes, bytes_to_file

from . import EncodingType


# --------------------------------------------------------------------------- #


__all__ = ["X509Cert"]

LOG = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #


class X509Cert:
    """
    High level abstraction for X509 Certificates.

    This class is used to hide implementation level details for how
    X509 certificates are actually handled.
    """

    # Implementation Variables:
    #   __cert:     The underlying x509.Certificate object from Cryptography
    #   __encoding: The underlying variable for the encoding getter/setter

    @classmethod
    def from_file(cls, path: str) -> "X509Cert":
        """
        Create a new X509Cert object from the given file.

        :param path: The path of the certificate file to load.

        :return: A new ``X509Cert`` representing the loaded file.

        :raises FileNotFoundError: If the given cert. file could not be found.
        """
        return cls(file_to_bytes(path))

    def __init__(self, data: bytes):
        """
        Creates a new X509 object from the given bytes.

        Changing the produced object will NOT change the underlying
        bytes. The new object must first be exported.

        :param data: The bytes of the certificate to load.

        :return: A new ``X509Cert`` representing the loaded certificate.

        :raises TypeError: If the value for ``data`` cannot be treated
         as bytes.
        :raises ValueError: If the given value for ``data`` cannot be properly
         decoded
        """
        if isinstance(data, str):
            data = data.encode()

        if not isinstance(data, bytes):
            raise TypeError("Value of 'data' must be bytes")

        backend = default_backend()
        self.__encoding = None
        # (1)   Try loading as DER
        try:
            self.__cert = x509.load_der_x509_certificate(data, backend)
            self.encoding = EncodingType.DER
        except ValueError:
            # (2)   Try loading as PEM
            try:
                self.__cert = x509.load_pem_x509_certificate(data, backend)
                self.encoding = EncodingType.PEM
            except ValueError:
                # Could not load - bytes not in suitable format.
                raise ValueError("Could not find a suitable encoding for "
                                 "'data' bytes")

    def __bytes__(self):
        return self.public_bytes()

    @property
    def encoding(self) -> EncodingType:
        """
        Returns the certificate serialization encoding.
        """
        return self.__encoding

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

    def public_bytes(self, *, encoding: EncodingType = None) -> bytes:
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
        return self.__cert.public_bytes(encoding)

    def to_file(self, path: str, *, encoding: EncodingType = None) -> None:
        """
        Writes the certificate to a file, serialized according to the
        value of the ``encoding`` instance attribute.

        :param path: The path at which to write the file.
        :param encoding: Override the object's encoding before writing to the
         file.

        :raises PermissionError: If the file could not be written.
        """
        encoding = encoding or self.encoding
        bytes_to_file(path, self.public_bytes(encoding=encoding))
