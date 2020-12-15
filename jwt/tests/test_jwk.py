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

import json
import unittest

from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)

from jwt.jwk import (
    OctetJWK,
    RSAJWK,

    jwk_from_dict,
    jwk_from_pem,
    jwk_from_der,
    jwk_from_bytes,
    jwk_from_bytes_argument_conversion,

    MalformedJWKError,
    UnsupportedKeyTypeError,
)

from pytest import raises

from .helper import load_testdata


def test_jwk_from_pem():
    jwk_priv = jwk_from_pem(load_testdata('rsa_privkey.pem'))

    assert isinstance(jwk_priv, RSAJWK)
    assert isinstance(jwk_priv.keyobj, RSAPrivateKey)


def test_jwk_from_dict():
    jwk_priv = jwk_from_dict(
        json.loads(load_testdata('rsa_privkey.json', 'r')))

    assert isinstance(jwk_priv, RSAJWK)
    assert isinstance(jwk_priv.keyobj, RSAPrivateKey)


def test_jwk_from_dict_malformed_kty():
    json_priv = json.loads(load_testdata('rsa_privkey.json', 'r'))
    del json_priv['kty']
    with raises(MalformedJWKError):
        jwk_from_dict(json_priv)


def test_jwk_from_dict_unsupported_kty():
    json_priv = json.loads(load_testdata('rsa_privkey.json', 'r'))
    json_priv['kty'] = 'unknown'
    with raises(UnsupportedKeyTypeError):
        jwk_from_dict(json_priv)


def test_jwk_from_bytes_argument_conversion_confusing_name():
    with raises(Exception) as ex:
        @jwk_from_bytes_argument_conversion
        def confusing():  # pylint: disable=unused-variable  # pragma: no cover
            pass
    assert ("the wrapped function must have either public"
            " or private in it's name" in str(ex))


def test_jwk_from_bytes_without_load_function():
    with raises(Exception) as ex:
        jwk_from_bytes(b'')
    assert 'is not Optional' in str(ex)


def test_jwk_from_unsupported_pem():
    with raises(UnsupportedKeyTypeError):
        jwk_from_pem(load_testdata('dsa_privkey.pem'))


def test_jwk_from_pem_not_deserializable():
    with raises(UnsupportedKeyTypeError):
        jwk_from_pem(b'')


def test_jwk_from_der():
    jwk_priv = jwk_from_der(load_testdata('rsa_privkey.der'))

    assert isinstance(jwk_priv, RSAJWK)
    assert isinstance(jwk_priv.keyobj, RSAPrivateKey)


class OctetJWKTest(unittest.TestCase):

    def setUp(self):
        self.key_json = json.loads(load_testdata('oct.json', 'r'))
        self.inst = OctetJWK.from_dict(self.key_json)

    def test_get_kty(self):
        self.assertEqual(self.inst.get_kty(), 'oct')

    def test_get_kid(self):
        self.assertEqual(
            self.inst.get_kid(), 'HMAC key used in JWS A.1 example')

    def test_is_sign_key(self):
        self.assertTrue(self.inst.is_sign_key())

    def test_to_dict(self):
        self.assertEqual(self.inst.to_dict(public_only=False), self.key_json)

    def test_from_dict_missing_k(self):
        key_json = self.key_json.copy()
        del key_json['k']
        with raises(MalformedJWKError):
            OctetJWK.from_dict(key_json)


class RSAJWKTest(unittest.TestCase):

    def setUp(self):
        self.privkey_pem = load_testdata('rsa_privkey.pem')
        self.inst_priv = jwk_from_pem(self.privkey_pem)

        self.pubkey_pem = load_testdata('rsa_pubkey.pem')
        self.inst_pub = jwk_from_pem(self.pubkey_pem)

        self.privkey_json = json.loads(
            load_testdata('rsa_privkey.json', 'r'))
        self.privkey_full_json = json.loads(
            load_testdata('rsa_privkey_full.json', 'r'))
        self.pubkey_json = json.loads(
            load_testdata('rsa_pubkey.json', 'r'))

    def test_is_sign_key(self):
        self.assertTrue(self.inst_priv.is_sign_key())
        self.assertFalse(self.inst_pub.is_sign_key())

    def test_get_kty(self):
        self.assertEqual(self.inst_priv.get_kty(), 'RSA')
        self.assertEqual(self.inst_pub.get_kty(), 'RSA')

    def test_to_dict_pub(self):
        self.assertEqual(
            self.inst_pub.to_dict(public_only=False),
            self.pubkey_json)

    def test_to_dict_priv(self):
        self.assertEqual(
            self.inst_priv.to_dict(public_only=False),
            self.privkey_full_json)

    def test_to_dict_pubonly(self):
        self.assertEqual(
            self.inst_priv.to_dict(public_only=True),
            self.inst_pub.to_dict())

    def test_from_dict_pub(self):
        inst = RSAJWK.from_dict(self.pubkey_json)
        self.assertIsInstance(inst, RSAJWK)
        self.assertIsInstance(inst.keyobj, RSAPublicKey)

        self.assertEqual(inst.to_dict(public_only=False), self.pubkey_json)

    def test_from_dict_priv_full(self):
        inst = RSAJWK.from_dict(self.privkey_full_json)
        self.assertIsInstance(inst, RSAJWK)
        self.assertIsInstance(inst.keyobj, RSAPrivateKey)

        self.assertEqual(
            inst.to_dict(public_only=False), self.privkey_full_json)

    def test_from_dict_priv_oth_unsupported(self):
        with raises(UnsupportedKeyTypeError):
            _json = self.privkey_full_json.copy()
            _json['oth'] = 'unsupported'
            RSAJWK.from_dict(_json)

    def test_from_dict_priv_malformed_e(self):
        with raises(MalformedJWKError):
            _json = self.privkey_full_json.copy()
            del _json['e']
            RSAJWK.from_dict(_json)

    def test_from_dict_priv_malformed_q(self):
        with raises(MalformedJWKError):
            _json = self.privkey_full_json.copy()
            del _json['q']
            RSAJWK.from_dict(_json)

    def test_verify_invalid(self):
        from cryptography.hazmat.primitives.hashes import SHA256
        inst = RSAJWK.from_dict(self.privkey_full_json)
        assert not inst.verify(b'hello everyone', b'', hash_fun=SHA256)
