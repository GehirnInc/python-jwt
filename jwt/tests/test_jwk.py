# -*- coding: utf-8 -*-

import unittest

from jwt.utils import (
    int_to_base64,
    b64_decode,
)


class OctKeyTest(unittest.TestCase):

    @property
    def target(self):
        from jwt.jwk import OctKey
        return OctKey

    def setUp(self):
        self.jwk = {
            'k': 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3'
                 'Yj0iPS4hcgUuTwjAzZr1Z9CAow',
            'kid': 'HMAC key used in JWS A.1 example',
        }

    def test_from_dict(self):
        inst = self.target.from_dict(self.jwk)
        self.assertEqual(inst.kty, 'oct')
        self.assertEqual(inst.kid, 'HMAC key used in JWS A.1 example')
        self.assertEqual(inst.k, b64_decode(self.jwk['k']))

    def test_to_dict(self):
        expected = self.jwk.copy()
        expected.update({
            'kty': 'oct',
        })

        inst = self.target.from_dict(self.jwk)
        self.assertEqual(inst.to_dict(), expected)


class RSAKeyTest(unittest.TestCase):

    @property
    def target(self):
        from jwt.jwk import RSAKey
        return RSAKey

    def setUp(self):
        self.jwk = {
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
        }

    def test_from_dict(self):
        inst = self.target.from_dict(self.jwk)

        self.assertEqual(inst.kty, 'RSA')
        self.assertEqual(inst.kid, '2011-04-29')
        self.assertEqual(int_to_base64(inst.n), self.jwk['n'])
        self.assertEqual(int_to_base64(inst.e), self.jwk['e'])
        self.assertEqual(int_to_base64(inst.d), self.jwk['d'])
        self.assertEqual(dict(inst), {
            'alg': 'RS256',
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
        })

    def test_to_dict(self):
        expected = self.jwk.copy()
        expected.update({
            'kty': 'RSA',
        })

        inst = self.target.from_dict(self.jwk)
        self.assertEqual(inst.to_dict(), expected)


class JWKSetTest(unittest.TestCase):

    @property
    def target(self):
        from jwt.jwk import JWKSet
        return JWKSet

    def setUp(self):
        self.jwk = {
            'keys': [
                {
                    'kty': 'oct',
                    'alg': 'A128KW',
                    'k': 'GawgguFyGrWKav7AX4VKUg'
                },
                {
                    'kty': 'oct',
                    'k': 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH'
                         '75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
                    'kid': 'HMAC key used in JWS A.1 example'
                }
            ]
        }

    def test_to_dict(self):
        inst = self.target.from_dict(self.jwk)
        self.assertEqual(inst.to_dict(), self.jwk)
