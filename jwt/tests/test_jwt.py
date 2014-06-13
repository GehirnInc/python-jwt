# -*- coding: utf-8 -*-

import json
import unittest
from collections import OrderedDict

from jwt import (
    Impl,
    JWT,
)
from jwt.exceptions import (
    MalformedJWT,
    UnsupportedAlgorithm,
)
from jwt.jws import JWS


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
            inst.is_supported('none')

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
        self.jws = JWS()

    def test_encode(self):
        inst = JWT(self.jws)
        self.assertEqual(
            inst.encode(dict(alg='none'), ''),
            b'eyJhbGciOiAibm9uZSJ9..'
        )

    def test_encode_unknown_alg(self):
        inst = JWT(self.jws)
        with self.assertRaises(UnsupportedAlgorithm):
            inst.encode(dict(alg='unknown'), '')

    def test_encode_invalid_header(self):
        inst = JWT(self.jws)
        with self.assertRaises(MalformedJWT):
            inst.encode(dict(), '')

    def test_encode_nested(self):
        inst = JWT(self.jws)
        message = inst.encode(dict(alg='none'), '')
        headerobj = OrderedDict()
        headerobj['alg'] = 'none'
        headerobj['cty'] = 'JWT'
        self.assertEqual(
            inst.encode(headerobj, message),
            b'.'.join((
                b'eyJhbGciOiAibm9uZSIsICJjdHkiOiAiSldUIn0',
                b'ZXlKaGJHY2lPaUFpYm05dVpTSjkuLg',
                b''
            ))
        )

    def test_decode(self):
        inst = JWT(self.jws)
        ret = b'.'.join((
            b'eyJhbGciOiAibm9uZSJ9',
            b'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt'
            b'cGxlLmNvbS9pc19yb290Ijp0cnVlfQ',
            b'',
        ))
        self.assertEqual(
            json.loads(inst.decode(ret)),
            {
                'iss': 'joe',
                'exp': 1300819380,
                'http://example.com/is_root': True,
            }
        )

    def test_decode_invalid_jwt(self):
        inst = JWT(self.jws)
        with self.assertRaises(MalformedJWT):
            inst.decode(b'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9')

    def test_decode_invalid_header(self):
        inst = JWT(self.jws)
        ret = b'.'.join((
            b'e30',
            b'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt'
            b'cGxlLmNvbS9pc19yb290Ijp0cnVlfQ',
            b'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
        ))
        with self.assertRaises(MalformedJWT):
            inst.decode(ret)

    def test_decode_invalid_signature(self):
        inst = JWT(self.jws)
        ret = b'.'.join((
            b'eyJhbGciOiAibm9uZSIsICJjdHkiOiAiSldUIn0',
            b'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt'
            b'cGxlLmNvbS9pc19yb290Ijp0cnVlfQ',
            b'invalidsignature',
        ))
        with self.assertRaises(MalformedJWT):
            inst.decode(ret)

    def test_decode_nested(self):
        inst = JWT(self.jws)
        ret = b'.'.join((
            b'eyJhbGciOiAibm9uZSIsICJjdHkiOiAiSldUIn0',
            b'ZXlKaGJHY2lPaUFpYm05dVpTSjkuZXlKcGMzTWlPaUpxYjJVaUxBMEtJQ0psZUhB'
            b'aU9qRXpNREE0TVRrek9EQXNEUW9nSW1oMGRIQTZMeTlsZUdGdGNHeGxMbU52YlM5'
            b'cGMxOXliMjkwSWpwMGNuVmxmUS4',
            b''
        ))
        self.assertEqual(
            json.loads(inst.decode(ret)),
            {
                'iss': 'joe',
                'exp': 1300819380,
                'http://example.com/is_root': True,
            }
        )

    def test_verify(self):
        inst = JWT(self.jws)

        ret = b'.'.join((
            b'eyJhbGciOiAibm9uZSIsICJjdHkiOiAiSldUIn0',
            b'ZXlKaGJHY2lPaUFpYm05dVpTSjkuZXlKcGMzTWlPaUpxYjJVaUxBMEtJQ0psZUhB'
            b'aU9qRXpNREE0TVRrek9EQXNEUW9nSW1oMGRIQTZMeTlsZUdGdGNHeGxMbU52YlM5'
            b'cGMxOXliMjkwSWpwMGNuVmxmUS4',
            b'',
        ))
        self.assertTrue(inst.verify(ret))

    def test_verify_nested(self):
        inst = JWT(self.jws)

        ret = b'.'.join((
            b'eyJhbGciOiAibm9uZSIsICJjdHkiOiAiSldUIn0',
            b'ZXlKaGJHY2lPaUFpYm05dVpTSjkuLg',
            b''
        ))
        self.assertTrue(inst.verify(ret))
