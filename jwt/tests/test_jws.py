# -*- coding: utf-8 -*-

import hashlib
import unittest


class TestSigners(unittest.TestCase):

    def setUp(self):
        from jwt.jwk import JWK

        self.oct_key = JWK.from_dict({
            'kty': 'oct',
            'k': 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3'
                 'Yj0iPS4hcgUuTwjAzZr1Z9CAow'
        }).keyobj

        self.rsa_key = JWK.from_dict({
            'kty': 'RSA',
            'n': '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtV'
                 'T86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64t'
                 'Z_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2Q'
                 'vzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbO'
                 'pbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_'
                 'xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
            'e': 'AQAB',
            'd': 'X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7'
                 'GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3R'
                 'TzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d'
                 '_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IB'
                 'TNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lG'
                 'VkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q',
            'p': '83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R'
                 '-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWl'
                 'WEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs',
            'q': '3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO'
                 '1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkI'
                 'drecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk',
            'dp': 'G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2'
                  'emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuY'
                  'Zc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0',
            'dq': 's9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcM'
                  'pn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9G'
                  'F4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk',
            'qi': 'GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVF'
                  'EcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxy'
                  'R8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU',
            'alg': 'RS256',
            'kid': '2011-04-29'
        }).keyobj

    def test_plaintext_jwt(self):
        from jwt.jws import plaintext_jwt
        self.assertEqual(plaintext_jwt.sign(None, b'test'), b'')

    def verify_hmac_signature(self, signer, hash_func):
        import hmac
        message = b'This message will be signed'

        expected = hmac.new(self.oct_key, message, hash_func).digest()
        assert signer.sign(self.oct_key, message) == expected

    def test_hmac_signer(self):
        from jwt.jws import (
            hmac_signer,
            JWS,
        )

        signer = hmac_signer('alg', hashlib.sha256)

        self.assertIn('alg', JWS.REGISTRY)
        self.assertEqual(JWS.REGISTRY['alg'], signer)
        self.verify_hmac_signature(signer, hashlib.sha256)

    def test_hs256(self):
        from jwt.jws import hs256

        self.verify_hmac_signature(hs256, hashlib.sha256)

    def test_hs384(self):
        from jwt.jws import hs384

        self.verify_hmac_signature(hs384, hashlib.sha384)

    def test_hs512(self):
        from jwt.jws import hs512

        self.verify_hmac_signature(hs512, hashlib.sha512)

    def verify_rsa_signature(self, signer, hash_func):
        from Crypto.Signature import PKCS1_v1_5
        message = b'This message will be signed'

        verifier = PKCS1_v1_5.new(self.rsa_key.publickey())
        assert verifier.verify(hash_func.new(message),
                               signer.sign(self.rsa_key, message))
        assert signer.verify(self.rsa_key, message,
                             signer.sign(self.rsa_key, message))

    def test_rsa_signer(self):
        from Crypto.Hash import SHA256
        from jwt.jws import (
            rsa_signer,
            JWS,
        )

        signer = rsa_signer('alg', SHA256)

        self.assertIn('alg', JWS.REGISTRY)
        self.assertEqual(JWS.REGISTRY['alg'], signer)
        self.verify_rsa_signature(signer, SHA256)

    def test_rs256(self):
        from Crypto.Hash import SHA256
        from jwt.jws import rs256

        self.verify_rsa_signature(rs256, SHA256)

    def test_rs384(self):
        from Crypto.Hash import SHA384
        from jwt.jws import rs384

        self.verify_rsa_signature(rs384, SHA384)

    def test_rs512(self):
        from Crypto.Hash import SHA512
        from jwt.jws import rs512

        self.verify_rsa_signature(rs512, SHA512)


class TestJWS(unittest.TestCase):

    @property
    def target(self):
        from jwt.jws import JWS
        return JWS

    def setUp(self):
        from jwt.jwk import (
            JWK,
            JWKSet,
        )

        self.keys = JWKSet()
        self.keys.append(JWK.from_dict({
            'kty': 'oct',
            'k': 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3'
                 'Yj0iPS4hcgUuTwjAzZr1Z9CAow'
        }))
        self.keys.append(JWK.from_dict({
            'kty': 'RSA',
            'n': 'ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHm'
                 'fHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_'
                 'YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5'
                 'z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uD'
                 'Zlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9ia'
                 'GNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ',
            'e': 'AQAB',
            'd': 'Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97Ijl'
                 'A7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTG'
                 'oVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M'
                 '_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQ'
                 'UShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB'
                 '4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ'
        }))

    def test_is_supported(self):
        inst = self.target(self.keys)

        for alg in {'none', 'HS256', 'RS256'}:
            self.assertTrue(inst.is_supported(alg))

        self.assertFalse(inst.is_supported('unknownalg'))

    def test_get_signer(self):
        inst = self.target(self.keys)

        from jwt.exceptions import UnsupportedAlgorithm
        from jwt.jws import (
            hs256,
            rs256,
        )

        self.assertEqual(inst.get_signer('HS256'), hs256)
        self.assertEqual(inst.get_signer('RS256'), rs256)

        with self.assertRaises(UnsupportedAlgorithm):
            inst.get_signer('unknownalg')

    def test_get_key(self):
        inst = self.target(self.keys)

        from jwt.jws import KeyNotFound

        with self.assertRaises(KeyNotFound):
            inst.get_key('unknownalg')

    def test_sign(self):
        inst = self.target(self.keys)

        self.assertEqual(
            inst.sign('none', b'This message will be signed', None),
            b'')

        self.assertEqual(
            inst.sign('HS256', b'This message will be signed', None),
            b'\xab\x9e\x1a\xb0\xaf\x99<\xf3\x07hS\xfc\x83h3\xa6\x95\x90\xbb'
            b'\x9e]Xa\xcagl\x1e\xbf\xc4\xb7Y\x0c')

        self.assertEqual(
            inst.sign('RS256', b'This message will be signed', None),
            b'\x87\xf8\x17\xd2\x07\xd1\t\xdf=4\xf8)\x98K\xfd0(\xa9\xd7\xa7\x06'
            b'\x19\xdf\x0cK\xfb\rL\xbf>\x04C\xca\x8c\xec\xf7V\xf36]\x82\xdeDq0'
            b'\xbeN(\xed}\x10J\xe6\xb3\xaa\xa7\x870\xc3\t\x05\x7f\x98i\xec\x1c'
            b'\xbf\x82\x9b\xf8\xde\xe9\x8c\x88\xd1\xf6G<\xff+\x11^\xad\';sMn'
            b'\x80\xf4\xbd\xe3\x9b\x07%^\xe9\xa8t\xa9^\xb9oC\xfbO-%*\xc8\xb7'
            b'\x80\xc9\xb8\x02:\xa9\x88\x18\xea\xe99\xcb\x86H\xe7R\x8f\xdd\xa0'
            b']\xa4\x04R\xc5\xff\xaf\xb8[\xf2\x99Z\xc7\x85\xcch[\xe2\x1e\xe0'
            b'\xe2\xd8\xe4\x15\x8e\x7fiI\xdf\xbdTA\xd6\x9fa\xaa\x9c\xbe3\xed'
            b'\xa1?\x91W\xd0\x87m\xbc\x08c\xfc\xc4\xb2v\x18\'\xaej\xc6\xba<'
            b'\xad\x7f\x84\x1dc^\x93\xa7\xb9&I\x1c\xc6\xbf\xb8\x99T\x0c3B\x8b'
            b'\x90j#p\xec\xc6`\xf14\x17\x84Y\xf1\x91\x82o\xf9>v0\xa5H\x82\xbdn'
            b'|\x84!`R\x17n\xdeV\x17D\x1fdv\x13\x80\x04\xec\x94')

    def test_verify(self):
        from jwt.exceptions import MalformedJWT

        inst = self.target(self.keys)
        encoded_payload = 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQog' +\
                          'Imh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ'

        headerobj = dict(alg='HS256', typ='JWT')
        encoded_header = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9'
        encoded_signature = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'

        self.assertTrue(inst.verify(
            headerobj, encoded_header,
            '.'.join((encoded_payload, encoded_signature))
        ))

        self.assertFalse(inst.verify(
            headerobj, encoded_header,
            '{payload}.dummysignature'.format(payload=encoded_payload)))

        with self.assertRaises(MalformedJWT):
            inst.verify(headerobj, encoded_header, encoded_signature)

        headerobj = dict(alg='RS256')
        encoded_header = 'eyJhbGciOiJSUzI1NiJ9'
        encoded_payload = 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQog' +\
                          'Imh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
        encoded_signature = 'cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQg' +\
                            'r9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5' +\
                            'jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB' +\
                            '--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb' +\
                            '1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC' +\
                            '-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QO' +\
                            'YEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0' +\
                            'igcN_IoypGlUPQGe77Rw'
        self.assertTrue(inst.verify(
            headerobj, encoded_header,
            '.'.join((encoded_payload, encoded_signature))))

    def test_encode(self):
        inst = self.target(self.keys)

        payload = b'{"iss":"joe",\r\n "exp":1300819380,\r\n ' +\
                  b'"http://example.com/is_root":true}'

        headerobj = dict(alg='HS256', typ='JWT')
        encoded_header = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9'
        self.assertEqual(
            inst.encode(headerobj, encoded_header, payload),
            'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtc'
            'GxlLmNvbS9pc19yb290Ijp0cnVlfQ.'
            'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')

        headerobj = dict(alg='RS256')
        encoded_header = 'eyJhbGciOiJSUzI1NiJ9'
        self.assertEqual(
            inst.encode(headerobj, encoded_header, payload),
            'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtc'
            'GxlLmNvbS9pc19yb290Ijp0cnVlfQ.'
            'cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7A'
            'AuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BA'
            'ynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0Ga'
            'rZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1p'
            'hCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igc'
            'N_IoypGlUPQGe77Rw')

    def test_decode(self):
        from jwt.jws import MalformedJWT

        inst = self.target(self.keys)

        payload = b'{"iss":"joe",\r\n "exp":1300819380,\r\n ' +\
                  b'"http://example.com/is_root":true}'
        encoded_payload = 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQog' +\
                          'Imh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ'

        with self.assertRaises(MalformedJWT):
            inst.decode({'alg': 'none'}, encoded_payload)

        headerobj = dict(alg='HS256', typ='JWT')
        encoded_signature = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
        self.assertEqual(
            inst.decode(headerobj, '{payload}.{signature}'.format(
                payload=encoded_payload, signature=encoded_signature
            )),
            payload)

        headerobj = dict(alg='RS256')
        encoded_payload = 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQog' +\
                          'Imh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
        encoded_signature = 'cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQg' +\
                            'r9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5' +\
                            'jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB' +\
                            '--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb' +\
                            '1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC' +\
                            '-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QO' +\
                            'YEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0' +\
                            'igcN_IoypGlUPQGe77Rw'
        self.assertEqual(
            inst.decode(headerobj, '{payload}.{signature}'.format(
                payload=encoded_payload, signature=encoded_signature
            )),
            payload)
