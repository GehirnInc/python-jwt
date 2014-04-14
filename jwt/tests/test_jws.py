# -*- coding: utf-8 -*-

import json
import unittest

from .. import utils
from ..jwk import JWK
from ..jws import (
    JWS,
    KeyNotFound,
    MalformedJWS,
    SIGNERS,
)
from ..jwt import NotSupported


class TestJWS(unittest.TestCase):

    def setUp(self):
        self.key1 = JWK.decode(
            b'{"kty":"oct",'
            b'"k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75'
            b'aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"'
            b'}'
        )
        self.key2 = JWK.decode(
            b'{"kty":"oct",'
            b'"k":"AB4RgZChQDrPSfgJNtwp0HLc-MnUi8FlFy0rBV_wUAGIE6awLXyA0U'
            b'w3HR298T_5_NCBBbOUdqR-_wyY1lL1-A"'
            b'}'
        )

    def test_get_key(self):
        inst = JWS(self.key1)
        inst.register_key('yakey', self.key2)

        self.assertIs(inst.get_key(None), self.key1)
        self.assertIs(inst.get_key('yakey'), self.key2)

        inst = JWS()
        with self.assertRaises(KeyNotFound):
            inst.get_key(None)

        with self.assertRaises(KeyNotFound):
            inst.get_key('dummykid')

    def test_is_supported(self):
        inst = JWS()

        for alg in {'none', 'HS256'}:
            self.assertTrue(inst.is_supported(alg))

        self.assertFalse(inst.is_supported('unknownalg'))

    def test_get_signer(self):
        inst = JWS()

        for alg in {'none', 'HS256'}:
            signer = inst.get_signer(alg)
            self.assertEqual(SIGNERS[alg], signer)

        with self.assertRaises(NotSupported):
            inst.get_signer('unknownalg')

    def test_encode(self):
        inst = JWS(self.key1)

        headerobj = dict(alg='HS256')
        header = utils.b64_encode(json.dumps(headerobj).encode('utf8'))
        payload = b''

        self.assertEqual(
            inst.encode(headerobj, header, payload),
            b'.'.join((
                payload,
                b't_zltwqKiJgaHhJaTBLqDWoHqRlZJIkql6t7EPsHltQ'
            )),
        )

    def test_decode(self):
        inst = JWS(self.key1)

        self.assertEqual(
            inst.decode(
                dict(alg='HS256'),
                b'.t_zltwqKiJgaHhJaTBLqDWoHqRlZJIkql6t7EPsHltQ',
            ),
            b'',
        )

        with self.assertRaises(MalformedJWS):
            inst.decode(
                dict(alg='HS256'),
                b't_zltwqKiJgaHhJaTBLqDWoHqRlZJIkql6t7EPsHltQ',
            ),

        with self.assertRaises(MalformedJWS):
            inst.decode(
                dict(alg='HS256'),
                b'eyJhbGciOiAiSFMyNTYifQ..'
                b't_zltwqKiJgaHhJaTBLqDWoHqRlZJIkql6t7EPsHltQ',
            ),

    def test_verify(self):
        inst = JWS(self.key1)

        payload = b'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQog' +\
            b'Imh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ'

        headerobj = dict(alg='HS256')
        header = utils.b64_encode(json.dumps(headerobj).encode('utf8'))
        rest = b'.t_zltwqKiJgaHhJaTBLqDWoHqRlZJIkql6t7EPsHltQ'

        self.assertTrue(inst.verify(headerobj, header, rest))
        self.assertFalse(inst.verify(headerobj, header, payload + rest))

        with self.assertRaises(MalformedJWS):
            inst.verify(headerobj, header, rest[1:])

        with self.assertRaises(MalformedJWS):
            inst.verify(headerobj, header, payload + b'.' + rest)
