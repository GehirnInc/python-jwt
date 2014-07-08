# -*- coding: utf-8 -*-

from __future__ import absolute_import
import json

from jwt.exceptions import (
    KeyNotFound,
    MalformedJWT,
    UnsupportedAlgorithm,
)
from jwt.interfaces import Impl
from jwt.jws import JWS
from jwt.utils import (
    b64_decode,
    b64_encode,
)


class JWT(Impl):

    def __init__(self, keys):
        self.keys = keys

        self.jws = JWS(keys)
        self.jwe = None

    def _get_impl(self, alg):
        if self.jws.is_supported(alg):
            return self.jws
        elif self.jwe and self.jwe.is_supported(alg):
            return self.jwe

        raise UnsupportedAlgorithm(alg)

    def sign(self, alg, message, kid=None):
        return self.jws.sign(alg, message, kid)

    def verify(self, jwt):
        assert isinstance(jwt, str)

        encoded_header, rest = jwt.split('.', 1)
        headerobj = json.loads(b64_decode(encoded_header).decode('utf8'))
        impl = self._get_impl(headerobj['alg'])

        if headerobj.get('cty') == 'JWT':
            jwt = impl.decode(headerobj, rest)
            return self.verify(str(jwt.decode('utf8')))

        return impl.verify(headerobj, encoded_header, rest)

    def encode(self, headerobj, payload):
        assert isinstance(headerobj, dict)
        assert isinstance(payload, bytes)

        try:
            impl = self._get_impl(headerobj['alg'])
        except KeyError as why:
            raise MalformedJWT('\'alg\' is required')

        encoded_header = b64_encode(self._json_encode(headerobj))

        return '.'.join((
            encoded_header,
            impl.encode(headerobj, encoded_header, payload)
        ))

    def decode(self, jwt):
        assert isinstance(jwt, str)

        encoded_header, rest = jwt.split('.', 1)
        headerobj = json.loads(b64_decode(encoded_header).decode('utf8'))
        impl = self._get_impl(headerobj['alg'])

        if not impl.verify(headerobj, encoded_header, rest):
            raise MalformedJWT()

        payload = impl.decode(headerobj, rest)

        if headerobj.get('cty') == 'JWT':
            return self.decode(str(payload.decode('utf8')))

        return payload
