

from enum import Enum

from cryptography.hazmat.primitives import serialization


# --------------------------------------------------------------------------- #


class EncodingType(str, Enum):
    """
    Represents the different type of encodings used for raw byte representation
    of different crypto. objects.
    """
    PEM = serialization.Encoding.PEM.value
    DER = serialization.Encoding.DER.value
    OpenSSH = serialization.Encoding.OpenSSH.value
