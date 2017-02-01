# -*- coding: utf-8 -*-
#
# Copyright 2017 Gehirn Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import hashlib
import hmac
from typing import Callable

from cryptography.hazmat.primitives.hashes import (
    SHA256,
    SHA384,
    SHA512,
)

from .exceptions import InvalidKeyTypeError
from .jwk import AbstractJWKBase


class AbstractSigningAlgorithm:

    def sign(self, message: bytes, key: AbstractJWKBase) -> bytes:
        raise NotImplementedError()  # pragma: no cover

    def verify(self, message: bytes, key: AbstractJWKBase,
               signature: bytes) -> bool:
        raise NotImplementedError()  # pragma: no cover


class NoneAlgorithm(AbstractSigningAlgorithm):

    def sign(self, message: bytes, key: AbstractJWKBase) -> bytes:
        return b''

    def verify(self, message: bytes, key: AbstractJWKBase,
               signature: bytes) -> bool:
        return hmac.compare_digest(signature, b'')


none = NoneAlgorithm()


class HMACAlgorithm(AbstractSigningAlgorithm):

    def __init__(self, hash_fun: Callable) -> None:
        self.hash_fun = hash_fun

    def _check_key(self, key: AbstractJWKBase) -> None:
        if key.get_kty() != 'oct':
            raise InvalidKeyTypeError((
                'an octet key is required, but passed is {}'
            ).format(key.get_kty()))

    def _sign(self, message: bytes, key: bytes) -> bytes:
        return hmac.new(key, message, self.hash_fun).digest()

    def sign(self, message: bytes, key: AbstractJWKBase) -> bytes:
        self._check_key(key)
        return key.sign(message, signer=self._sign)

    def verify(self, message: bytes, key: AbstractJWKBase,
               signature: bytes) -> bool:
        self._check_key(key)
        return key.verify(message, signature, signer=self._sign)


HS256 = HMACAlgorithm(hashlib.sha256)
HS384 = HMACAlgorithm(hashlib.sha384)
HS512 = HMACAlgorithm(hashlib.sha512)


class RSAAlgorithm(AbstractSigningAlgorithm):

    def __init__(self, hash_fun: object) -> None:
        self.hash_fun = hash_fun

    def _check_key(self, key: AbstractJWKBase, must_sign_key=False) -> None:
        if key.get_kty() != 'RSA':
            raise InvalidKeyTypeError((
                'a RSA key is required, but passed is {}'
            ).format(key.get_kty()))
        if must_sign_key and not key.is_sign_key():
            raise InvalidKeyTypeError(
                'a RSA private key is required, but passed is RSA public key')

    def sign(self, message: bytes, key: AbstractJWKBase) -> bytes:
        self._check_key(key, must_sign_key=True)
        return key.sign(message, hash_fun=self.hash_fun)

    def verify(self, message: bytes, key: AbstractJWKBase,
               signature: bytes) -> bool:
        self._check_key(key)
        return key.verify(message, signature, hash_fun=self.hash_fun)


RS256 = RSAAlgorithm(SHA256)
RS384 = RSAAlgorithm(SHA384)
RS512 = RSAAlgorithm(SHA512)


def supported_signing_algorithms():
    return {
        'none': none,
        'HS256': HS256,
        'HS384': HS384,
        'HS512': HS512,
        'RS256': RS256,
        'RS384': RS384,
        'RS512': RS512,
       }
