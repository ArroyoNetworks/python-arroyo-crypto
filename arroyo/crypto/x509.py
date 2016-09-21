# --------------------------------------------------------------------------- #


import logging

from abc import ABCMeta, abstractmethod
import collections

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

from idna.core import InvalidCodepoint

from arroyo.crypto import PublicKey
from arroyo.utils import file_to_bytes, bytes_to_file

from . import EncodingType


# --------------------------------------------------------------------------- #

# Typing

from typing import Union, List
from arroyo.crypto import PrivateKey


_STR_LIST_TYPE = Union[List[str], str]


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

    def __ne__(self, other):
        return not self.__eq__(other)

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

    @classmethod
    def generate(cls, key: PrivateKey, subj_alt_dns_names: _STR_LIST_TYPE, *,
                 CN: str = None, O: str = None, OU: str = None, L: str = None,
                 ST: str = None, C: str = None):
        """
        Generates a new Certificate Signing Request (CSR) with the given
        parameters.

        :param key: Private key used to sign the CSR.
        :param subj_alt_dns_names: DNS name(s) to be included in the Subject
         Alternative Name (SAN).

        :param CN: Common Name, typically a wildcard name.
        :param O: Organization Name.
        :param OU: Organizational Unit Name.
        :param L: Locality or City Name.
        :param ST: State or Province Name.
        :param C: Country Name.

        :return: A new ``x509CertSignReq`` representing the newly generated
         csr.

        :raises ValueError: If the given value for a certificate field is not
         valid.
        """

        if isinstance(subj_alt_dns_names, str):
            subj_alt_dns_names = (subj_alt_dns_names, )

        if isinstance(subj_alt_dns_names, collections.Iterable):
            if len(subj_alt_dns_names) == 0:
                raise ValueError("At least one alternative subject name must "
                                 "be given.")

        # Build the Distinguished Name
        dn = []
        try:
            if CN:
                dn.append(x509.NameAttribute(NameOID.COMMON_NAME, CN))
            if O:
                dn.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, O))
            if OU:
                dn.append(
                    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, OU)
                )
            if L:
                dn.append(x509.NameAttribute(NameOID.LOCALITY_NAME, L))
            if ST:
                dn.append(
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, ST)
                )
            if C:
                dn.append(x509.NameAttribute(NameOID.COUNTRY_NAME, C))
        except ValueError as e:
            raise ValueError("Invalid value: {}".format(str(e)))

        # Build the SAN
        san = []
        for name in subj_alt_dns_names:
            san.append(x509.DNSName(name))

        # Build the CSR Parameters
        builder = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name(dn)
        ).add_extension(
            x509.SubjectAlternativeName(san),
            critical=False
        )

        # Sign the CSR
        private_key = serialization.load_der_private_key(
            key.to_bytes(encoding=EncodingType.DER),
            None,
            default_backend()
        )
        try:
            csr = builder.sign(private_key, hashes.SHA256(), default_backend())
        except InvalidCodepoint as e:
            raise ValueError("Invalid value: {}".format(str(e)))

        # Serialize the CSR to Bytes
        csr_bytes = csr.public_bytes(EncodingType.DER)

        return cls(data=csr_bytes)

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

    def get_subj_alt_dns_names(self) -> List:

        san = self._x509_obj.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )

        return san.value.get_values_for_type(x509.DNSName)

    def to_bytes(self, *, encoding: EncodingType = None) -> bytes:
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
