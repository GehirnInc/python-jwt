# -*- coding: utf-8 -*-

import hashlib
import hmac
import functools

from .jwt import (
    Impl,
    NotSupported,
)

__all__ = ['JWS', 'MalformedJWS', 'KeyNotFound']


MalformedJWS = type('MalformedJWS', (ValueError, ), {})


KeyNotFound = type('KeyNotFound', (ValueError, ), {})


SIGNERS = {}


def signer(name):
    def receive(func):
        SIGNERS[name] = func
        return func
    return receive


def hmac_signer(func):
    @functools.wraps(func)
    def sign(key, target):
        return hmac.new(key.k, target, func()).digest()
    return sign


@signer('none')
def plaintext_jwt(key, target):
    return b''


@signer('HS256')
@hmac_signer
def hmac_sha256():
    return hashlib.sha256


@signer('HS384')
@hmac_signer
def hmac_sha384():
    return hashlib.sha384


@signer('HS512')
@hmac_signer
def hmac_sha512():
    return hashlib.sha512


class JWS(Impl):

    def __init__(self, default_key=None):
        self.default_key = default_key
        self.keys = {}

    def register_key(self, kid, key):
        self.keys[kid] = key

    def get_key(self, kid=None):
        if kid is None:
            if self.default_key is None:
                raise KeyNotFound()

            return self.default_key

        try:
            return self.keys[kid]
        except KeyError as why:
            raise KeyNotFound('{kid}'.format(kid=kid)) from why

    def is_supported(self, alg, enc=None):
        return alg in SIGNERS

    def get_signer(self, alg):
        try:
            return SIGNERS[alg]
        except KeyError as why:
            raise NotSupported() from why

    def encode(self, headerobj, encoded_header, payload):
        assert isinstance(headerobj, dict)
        assert isinstance(encoded_header, bytes)
        assert isinstance(payload, bytes)

        if headerobj['alg'] == 'none':
            key = None
        else:
            key = self.get_key(headerobj.get('kid'))
        signer = self.get_signer(headerobj['alg'])

        encoded_payload = self._b64_encode(payload)
        encoded_signature = self._b64_encode(signer(
            key,
            b'.'.join((encoded_header, encoded_payload))
        ))
        return b'.'.join((encoded_payload, encoded_signature))

    def decode(self, headerobj, rest):
        assert isinstance(headerobj, dict)
        assert isinstance(rest, bytes)

        try:
            encoded_payload, _ = rest.split(b'.')
            return self._b64_decode(encoded_payload)
        except ValueError as why:
            raise MalformedJWS() from why

    def verify(self, headerobj, encoded_header, rest):
        assert isinstance(headerobj, dict)
        assert isinstance(encoded_header, bytes)
        assert isinstance(rest, bytes)

        try:
            encoded_payload, encoded_signature = rest.split(b'.')
        except ValueError as why:
            raise MalformedJWS() from why
        else:
            payload = self._b64_decode(encoded_payload)
            return self.encode(headerobj, encoded_header, payload) == rest
