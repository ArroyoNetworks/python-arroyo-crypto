====================
python-arroyo-crypto
====================

:Info: Provides x509 and Asymmetrical Key abstraction classes
:Repository: https://github.com/ArroyoNetworks/python-arroyo-crypto
:Author(s): Matthew Ellison (http://github.com/seglberg)
:Maintainer(s): Matthew Ellison (http://github.com/seglberg)

.. image:: https://travis-ci.org/ArroyoNetworks/python-arroyo-crypto.svg?branch=master
    :target: https://travis-ci.org/ArroyoNetworks/python-arroyo-crypto

.. image:: https://img.shields.io/codecov/c/github/ArroyoNetworks/python-arroyo-crypto/master.svg?maxAge=600
    :target: https://codecov.io/github/ArroyoNetworks/python-arroyo-crypto?branch=master
    
.. image:: https://img.shields.io/pypi/v/arroyo-crypto.svg
    :target: https://pypi.python.org/pypi/arroyo-crypto/

.. image:: https://img.shields.io/github/license/ArroyoNetworks/python-arroyo-crypto.svg
    :target: https://github.com/ArroyoNetworks/python-arroyo-crypto/blob/master/LICENSE


Introduction
============

.. contents:: Quick Start
   :depth: 2

This plugin package provides high-level cryptography abstraction classes,
including x509 and Asymmetrical Key classes.

If you require fine-tuned cryptography settings, consider using a more suitable
python package, such as `cryptography` or `pyopenssl`.


Installation
============
Arroyo Crypto is now available on PyPI:

.. code:: console

    $ pip install arroyo-crypto


Dependencies
============
Python 3.5 or greater

Required
--------

:arroyo: Provides the base package this plugin is being installed into.
:cryptography: Provides the implementation for x509 and asymmetrical keys.
