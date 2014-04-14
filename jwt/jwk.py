# -*- coding: utf-8 -*-

import json

from . import utils


InvalidKey = type('InvalidKey', (ValueError, ), {})


class JWK:

    @classmethod
    def decode(cls, jwk):
        assert isinstance(jwk, bytes)

        key = json.loads(jwk.decode('utf8'))
        if 'kty' not in key:
            raise InvalidKey()

        if key['kty'] == 'oct':
            return OctKey.from_dict(key)


class OctKey(JWK):

    def __init__(self, params):
        self.params = params

    def __getattr__(self, name):
        if name in self.params:
            return self.params[name]

        raise AttributeError(
            '{obj!r} object has no attribute \'{name!s}\''.format(
                obj=self, name=name
            )
        )

    @property
    def k(self):
        return utils.b64_decode(self.params['k'].encode('utf8'))

    @classmethod
    def from_dict(cls, key):
        assert key['kty'] == 'oct'
        assert 'k' in key

        return cls(key)
