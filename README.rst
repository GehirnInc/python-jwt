.. image:: https://travis-ci.org/GehirnInc/python-jwt.svg?branch=master
    :target: https://travis-ci.org/GehirnInc/python-jwt
.. image:: https://coveralls.io/repos/GehirnInc/python-jwt/badge.png?branch=master
    :target:  https://coveralls.io/r/GehirnInc/python-jwt?branch=master
.. image:: https://badge.fury.io/py/jwt.svg?dummy
    :target: http://badge.fury.io/py/jwt

python-jwt
==========

*python-jwt* is a JSON Web Token (JWT) implementation in Python developed by `Gehirn Inc`_.


Examples
--------

.. code-block:: python

   import json

   from jwt import (
       JWT,
       jwk_from_dict,
       jwk_from_pem,
   )

   message = {
       'iss': 'https://example.com/',
       'sub': 'yosida95',
       'iat': 1485969205,
       'exp': 1485972805,
   }

   with open('rsa_private_key.pem', 'rb') as fh:
       signing_key = jwk_from_pem(fh.read())

   jwt = JWT()
   compact_jws = jwt.encode(message, signing_key, 'RS256')

   with open('rsa_public_key.json', 'r') as fh:
       verifying_key = jwk_from_dict(json.load(fh))

   message_received = jwt.decode(compact_jws, verifying_key)

   assert message == message_received


Installation
------------

You can install python-jwt with pip.

.. code-block:: shell

   $ pip install jwt


Implementation Details
-------------------------

Supported Algorithms
~~~~~~~~~~~~~~~~~~~~

- Unsecured

  - none

- Symmetric

  - HS256

  - HS384

  - HS512

- Asymmetric

  - RS256

  - RS384

  - RS512

Supported Python Versions
~~~~~~~~~~~~~~~~~~~~~~~~~

- Python 3.4

- Python 3.5

- Python 3.6

- Python 3.7


License
-------
python-jwt is licensed under the Apache License version 2.  See ./LICENSE.rst.


.. _Gehirn Inc: http://www.gehirn.co.jp/
