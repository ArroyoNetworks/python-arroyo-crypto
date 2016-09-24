# --------------------------------------------------------------------------- #


import os
import tempfile
import string
import random

import pytest


from arroyo.crypto import KeyAlgorithmType


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


@pytest.fixture
def nonempty_file(empty_file):
    """
    Returns the path of an non-empty temp. file that will automatically be
    deleted when the test ends.
    """

    with open(empty_file, mode='wb') as f:
        f.write(os.urandom(100))

    return empty_file


@pytest.fixture
def nonexisting_file():
    """
    Returns the path to a file that does not exist on the filesystem.
    """
    filename = None
    while not filename or os.path.exists(filename):
        choices = string.ascii_letters
        r = ''.join(random.choice(choices + string.digits) for _ in range(25))
        filename = os.path.join("/", "tmp", r)
    return filename


@pytest.fixture(scope="session", params=KeyAlgorithmType)
def key_algorithm(request):
    return request.param
