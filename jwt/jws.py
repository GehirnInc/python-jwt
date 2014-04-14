# -*- coding: utf-8 -*-

import hashlib
import hmac

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
        except KeyError:
            raise KeyNotFound('{kid}'.format(kid=kid))

    def is_supported(self, alg, enc=None):
        return alg in SIGNERS

    def get_signer(self, alg):
        try:
            return SIGNERS[alg]
        except KeyError:
            raise NotSupported()

    def encode(self, headerobj, header, payload):
        assert isinstance(headerobj, dict)
        assert isinstance(payload, bytes)

        signer = self.get_signer(headerobj['alg'])
        signature = self._b64_encode(signer(
            self.get_key(headerobj.get('kid')),
            b'.'.join((header, payload))
        ))

        return b'.'.join((payload, signature))

    def decode(self, headerobj, rest):
        assert isinstance(headerobj, dict)
        assert isinstance(rest, bytes)

        try:
            payload, _ = rest.split(b'.')
        except ValueError:
            raise MalformedJWS()
        else:
            return payload

    def verify(self, headerobj, header, rest):
        assert isinstance(headerobj, dict)
        assert isinstance(header, bytes)
        assert isinstance(rest, bytes)

        try:
            payload, signature = rest.split(b'.')
        except ValueError:
            raise MalformedJWS()
        else:
            signer = self.get_signer(headerobj['alg'])
            expected = signer(
                self.get_key(headerobj.get('kid')),
                b'.'.join((header, payload))
            )

            return self._b64_decode(signature) == expected
