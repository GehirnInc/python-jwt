# -*- coding: utf-8 -*-

from __future__ import absolute_import

import hashlib
import hmac
from collections import namedtuple

from Crypto.Hash import (
    SHA256,
    SHA384,
    SHA512,
)
from Crypto.PublicKey.RSA import _RSAobj
from Crypto.Signature import PKCS1_v1_5

from jwt.exceptions import (
    InvalidKeyType,
    KeyNotFound,
    MalformedJWT,
    UnsupportedAlgorithm,
)
from jwt.interfaces import Impl
from jwt.utils import (
    b64_decode,
    b64_encode,
)

__all__ = ['JWS']


class JWS(Impl):

    REGISTRY = {}

    def __init__(self, keys):
        self.keys = keys

    def is_supported(self, alg):
        return alg in self.REGISTRY

    def get_signer(self, alg):
        try:
            return self.REGISTRY[alg]
        except KeyError as why:
            raise UnsupportedAlgorithm(alg)

    def get_key(self, alg, kid=None, needs_private=False):
        if alg.startswith('HS'):
            kty = 'oct'
        elif alg.startswith('RS'):
            kty = 'RSA'
        else:
            raise KeyNotFound()

        return self.keys.get(kty, kid, needs_private)

    def sign(self, alg, message, kid):
        assert isinstance(message, bytes)

        signer = self.get_signer(alg)
        if alg == 'none':
            return signer.sign(None, message)

        key = self.get_key(alg, kid, True)
        return signer.sign(key.keyobj, message)

    def _signing_message(self, encoded_header, encoded_payload):
        return '.'.join((encoded_header, encoded_payload)).encode('ascii')

    def verify(self, headerobj, encoded_header, rest):
        assert isinstance(headerobj, dict)
        assert isinstance(encoded_header, str)
        assert isinstance(rest, str)

        try:
            encoded_payload, encoded_signature = rest.split('.')
            signature = b64_decode(encoded_signature)
        except ValueError as why:
            raise MalformedJWT()
        else:
            msg = self._signing_message(encoded_header, encoded_payload)

            signer = self.get_signer(headerobj['alg'])
            if headerobj['alg'] == 'none':
                return signer.verify(None, msg, signature)

            key = self.get_key(headerobj['alg'], headerobj.get('kid'))
            return signer.verify(key.keyobj, msg, signature)

    def encode(self, headerobj, encoded_header, payload):
        assert isinstance(headerobj, dict)
        assert isinstance(encoded_header, str)
        assert isinstance(payload, bytes)

        encoded_payload = b64_encode(payload)
        encoded_signature = b64_encode(self.sign(
            headerobj['alg'],
            self._signing_message(encoded_header, encoded_payload),
            headerobj.get('kid')))

        return '.'.join((encoded_payload, encoded_signature))

    def decode(self, headerobj, rest):
        assert isinstance(headerobj, dict)
        assert isinstance(rest, str)

        try:
            encoded_payload, _ = rest.split('.')
            return b64_decode(encoded_payload)
        except ValueError as why:
            raise MalformedJWT()

    @classmethod
    def register(cls, alg):
        def receiver(func):
            signer = namedtuple(alg, ['sign', 'verify'])(*func())
            cls.REGISTRY[alg] = signer
            return signer
        return receiver


def hmac_signer(name, hashfunc):

    @JWS.register(name)
    def signer():

        def sign(key, message):
            if not isinstance(key, bytes):
                raise InvalidKeyType('Required oct key')

            return hmac.new(key, message, hashfunc).digest()

        def verify(key, message, signature):
            if not isinstance(key, bytes):
                raise InvalidKeyType('Required oct key')

            return sign(key, message) == signature

        return (sign, verify)

    return signer


def rsa_signer(name, hashfunc):

    @JWS.register(name)
    def signer():

        def sign(key, message):
            if not isinstance(key, _RSAobj):
                raise InvalidKeyType('Required RSA key')

            signer = PKCS1_v1_5.new(key)
            message_hash = hashfunc.new(message)
            return signer.sign(message_hash)

        def verify(key, message, signature):
            if not isinstance(key, _RSAobj):
                raise InvalidKeyType('Required RSA key')

            verifier = PKCS1_v1_5.new(key)
            message_hash = hashfunc.new(message)
            return verifier.verify(message_hash, signature)

        return (sign, verify)

    return signer


@JWS.register('none')
def plaintext_jwt():
    return (
        lambda key, message: b'',
        lambda key, message, signature: signature == b''
    )


hs256 = hmac_signer('HS256', hashlib.sha256)
hs384 = hmac_signer('HS384', hashlib.sha384)
hs512 = hmac_signer('HS512', hashlib.sha512)


rs256 = rsa_signer('RS256', SHA256)
rs384 = rsa_signer('RS384', SHA384)
rs512 = rsa_signer('RS512', SHA512)
