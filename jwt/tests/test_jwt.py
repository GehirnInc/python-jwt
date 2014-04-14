# -*- coding: utf-8 -*-

import json
import unittest

from ..jws import (
    JWS,
    KeyNotFound,
    NotSupported,
)
from ..jwt import (
    Impl,
    InvalidJWT,
    JWT,
    MalformedJWT,
)
from ..jwk import JWK


class ImplTest(unittest.TestCase):

    def test_json_encode(self):
        inst = Impl()

        ret = {
            'iss': 'joe',
            'exp': 1300819380,
            'http://example.com/is_root': True
        }
        encoded = inst._json_encode(ret)
        self.assertEqual(json.loads(encoded), ret)

    def test_json_decode(self):
        inst = Impl()

        ret = '{"iss":"joe",\r\n "exp":1300819380,\r\n ' \
            + '"http://example.com/is_root":true}'

        expected = {
            'iss': 'joe',
            'exp': 1300819380,
            'http://example.com/is_root': True
        }
        self.assertEqual(inst._json_decode(ret), expected)

    def test_is_supported(self):
        inst = Impl()

        with self.assertRaises(NotImplementedError):
            inst.is_supported('HS256')

    def test_encode(self):
        inst = Impl()

        with self.assertRaises(NotImplementedError):
            inst.encode({}, b'', b'')

    def test_decode(self):
        inst = Impl()

        with self.assertRaises(NotImplementedError):
            inst.decode({}, b'')

    def test_verify(self):
        inst = Impl()

        with self.assertRaises(NotImplementedError):
            inst.verify({}, b'',  b'')


class JWTTest(unittest.TestCase):

    def setUp(self):
        key = JWK.decode(
            b'{"kty":"oct",'
            b'"k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75'
            b'aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"'
            b'}'
        )
        self.jws = JWS(key)

    def test_encode(self):
        inst = JWT(self.jws)

        self.assertEqual(
            inst.encode(dict(alg='none'), b''),
            b'eyJhbGciOiAibm9uZSJ9..'
        )

        with self.assertRaises(NotSupported):
            inst.encode(dict(alg='unknown'), b'')

        with self.assertRaises(InvalidJWT):
            inst.encode(dict(), b'')

    def test_decode(self):
        inst = JWT(self.jws)
        ret = b'.'.join((
            b'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9',
            b'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt'
            b'cGxlLmNvbS9pc19yb290Ijp0cnVlfQ',
            b'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
        ))
        self.assertEqual(
            inst.decode(ret),
            {
                'iss': 'joe',
                'exp': 1300819380,
                'http://example.com/is_root': True,
            }
        )

        with self.assertRaises(MalformedJWT):
            inst.decode(b'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9')

        ret = b'.'.join((
            b'e30=',
            b'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt'
            b'cGxlLmNvbS9pc19yb290Ijp0cnVlfQ',
            b'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
        ))
        with self.assertRaises(InvalidJWT):
            inst.decode(ret)

    def test_verify(self):
        inst = JWT(self.jws)

        ret = b'.'.join((
            b'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9',
            b'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt'
            b'cGxlLmNvbS9pc19yb290Ijp0cnVlfQ',
            b'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
        ))
        self.assertTrue(inst.verify(ret))
