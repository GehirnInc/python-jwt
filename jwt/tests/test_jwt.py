# -*- coding: utf-8 -*-

import json
import unittest
from collections import OrderedDict

from jwt.exceptions import (
    MalformedJWT,
    UnsupportedAlgorithm,
)


class JWTTest(unittest.TestCase):

    @property
    def target(self):
        from jwt.jwt import JWT
        return JWT

    def setUp(self):
        from jwt.jwk import JWKSet
        self.keys = JWKSet()

    def test_encode(self):
        inst = self.target(self.keys)
        self.assertEqual(
            inst.encode(dict(alg='none'), b''),
            'eyJhbGciOiAibm9uZSJ9..'
        )

    def test_encode_unknown_alg(self):
        inst = self.target(self.keys)
        with self.assertRaises(UnsupportedAlgorithm):
            inst.encode(dict(alg='unknown'), b'')

    def test_encode_invalid_header(self):
        inst = self.target(self.keys)
        with self.assertRaises(MalformedJWT):
            inst.encode(dict(), b'')

    def test_encode_nested(self):
        inst = self.target(self.keys)
        message = inst.encode(dict(alg='none'), b'').encode('utf8')
        headerobj = OrderedDict()
        headerobj['alg'] = 'none'
        headerobj['cty'] = 'JWT'
        self.assertEqual(
            inst.encode(headerobj, message),
            '.'.join((
                'eyJhbGciOiAibm9uZSIsICJjdHkiOiAiSldUIn0',
                'ZXlKaGJHY2lPaUFpYm05dVpTSjkuLg',
                ''
            ))
        )

    def test_decode(self):
        inst = self.target(self.keys)
        payload = inst.decode('.'.join((
            'eyJhbGciOiAibm9uZSJ9',
            'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt'
            'cGxlLmNvbS9pc19yb290Ijp0cnVlfQ',
            ''
        ))).decode('utf8')

        self.assertEqual(
            json.loads(payload),
            {
                'iss': 'joe',
                'exp': 1300819380,
                'http://example.com/is_root': True,
            })

    def test_decode_nested(self):
        inst = self.target(self.keys)
        payload = inst.decode('.'.join((
            'eyJhbGciOiAibm9uZSIsICJjdHkiOiAiSldUIn0',
            'ZXlKaGJHY2lPaUFpYm05dVpTSjkuZXlKcGMzTWlPaUpxYjJVaUxBMEtJQ0psZUhB'
            'aU9qRXpNREE0TVRrek9EQXNEUW9nSW1oMGRIQTZMeTlsZUdGdGNHeGxMbU52YlM5'
            'cGMxOXliMjkwSWpwMGNuVmxmUS4',
            ''
        ))).decode('utf8')

        self.assertEqual(
            json.loads(payload),
            {
                'iss': 'joe',
                'exp': 1300819380,
                'http://example.com/is_root': True,
            })

    def test_verify(self):
        inst = self.target(self.keys)

        ret = '.'.join((
            'eyJhbGciOiAibm9uZSIsICJjdHkiOiAiSldUIn0',
            'ZXlKaGJHY2lPaUFpYm05dVpTSjkuZXlKcGMzTWlPaUpxYjJVaUxBMEtJQ0psZUhB'
            'aU9qRXpNREE0TVRrek9EQXNEUW9nSW1oMGRIQTZMeTlsZUdGdGNHeGxMbU52YlM5'
            'cGMxOXliMjkwSWpwMGNuVmxmUS4',
            '',
        ))
        self.assertTrue(inst.verify(ret))

    def test_verify_nested(self):
        inst = self.target(self.keys)

        ret = '.'.join((
            'eyJhbGciOiAibm9uZSIsICJjdHkiOiAiSldUIn0',
            'ZXlKaGJHY2lPaUFpYm05dVpTSjkuLg',
            ''
        ))
        self.assertTrue(inst.verify(ret))
