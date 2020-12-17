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
   from datetime import datetime, timedelta, timezone

   from jwt import (
       JWT,
       jwk_from_dict,
       jwk_from_pem,
   )
   from jwt.utils import get_int_from_datetime


   instance = JWT()

   message = {
       'iss': 'https://example.com/',
       'sub': 'yosida95',
       'iat': get_int_from_datetime(datetime.now(timezone.utc)),
       'exp': get_int_from_datetime(
           datetime.now(timezone.utc) + timedelta(hours=1)),
   }

   """
   Encode the message to JWT(JWS).
   """

   # Load a RSA key from a JWK dict.
   signing_key = jwk_from_dict({
       'kty': 'RSA',
       'e': 'AQAB',
       'n': '...',
       'd': '...'})
   # Or load a RSA key from a PEM file.
   with open('rsa_private_key.pem', 'rb') as fh:
       signing_key = jwk_from_pem(fh.read())
   # You can also load an octet key in the same manner as the RSA.
   # signing_key = jwk_from_dict({'kty': 'oct', 'k': '...'})

   compact_jws = instance.encode(message, signing_key, alg='RS256')

   """
   Decode the JWT with verifying the signature.
   """

   # Load a public key from PEM file corresponding to the signing private key.
   with open('rsa_public_key.json', 'r') as fh:
       verifying_key = jwk_from_dict(json.load(fh))

   message_received = instance.decode(
       compact_jws, verifying_key, do_time_check=True)

   """
   Successfuly retrieved the `message` from the `compact_jws`
   """
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

  - none (disabled by default for security)

- Symmetric

  - HS256
  - HS384
  - HS512

- Asymmetric

  - PS256
  - PS384
  - PS512
  - RS256
  - RS384
  - RS512

Supported Python Versions
~~~~~~~~~~~~~~~~~~~~~~~~~

- Python 3.6+


License
-------
python-jwt is licensed under the Apache License version 2.  See ./LICENSE.rst.


.. _Gehirn Inc: http://www.gehirn.co.jp/
