# -*- coding: utf-8 -*-

import json

from . import utils


InvalidJWT = type('InvalidJWT', (ValueError, ), {})


MalformedJWT = type('InvalidJWT', (ValueError, ), {})


NotSupported = type('InvalidJWT', (ValueError, ), {})


class Impl:

    def _json_encode(self, obj):
        assert isinstance(obj, dict)
        return json.dumps(obj)

    def _json_decode(self, encoded):
        assert isinstance(encoded, str)
        return json.loads(encoded)

    def _b64_encode(self, source):
        return utils.b64_encode(source)

    def _b64_decode(self, source):
        return utils.b64_decode(source)

    def is_supported(self, alg, enc=None):
        raise NotImplementedError

    def encode(self, headerobj, header, payload):
        raise NotImplementedError

    def decode(self, headerobj, rest):
        raise NotImplementedError

    def verify(self, headerobj, header, rest):
        raise NotImplementedError


class JWT(Impl):

    def __init__(self, jws, jwe=None):
        assert isinstance(jws, Impl)
        assert isinstance(jwe, (Impl, type(None)))

        self.jws = jws
        self.jwe = jwe

    def _get_impl(self, alg, enc=None):
        if self.jws.is_supported(alg):
            return self.jws
        elif self.jwe and self.jwe.is_supported(alg, enc):
            return self.jwe

        raise NotSupported(alg, enc)

    def _is_nested_jwt(self, header):
        return 'cty' in header and header['cty'] == 'JWT'

    def _parse(self, jwt):
        try:
            header, rest = jwt.split(b'.', 1)

            headerobj =\
                self._json_decode(self._b64_decode(header).decode('utf8'))
            impl = self._get_impl(headerobj['alg'], headerobj.get('enc'))
        except ValueError:
            raise MalformedJWT()
        except KeyError:
            raise InvalidJWT('\'alg\' is required')
        else:
            if impl.verify(headerobj, header, rest):
                return impl, headerobj, rest

            raise InvalidJWT()

    def encode(self, headerobj, payload):
        try:
            impl = self._get_impl(headerobj['alg'], headerobj.get('enc'))
        except KeyError:
            raise InvalidJWT('\'alg\' is required')
        else:
            header =\
                self._b64_encode(self._json_encode(headerobj).encode('utf8'))
            return b'.'.join((
                header, impl.encode(headerobj, header, payload)
            ))

    def decode(self, jwt):
        impl, headerobj, rest = self._parse(jwt)
        message = impl.decode(headerobj, rest)
        if self._is_nested_jwt(headerobj):
            return self.decode(message)

        return self._json_decode(self._b64_decode(message).decode('utf8'))

    def verify(self, jwt):
        impl, headerobj, rest = self._parse(jwt)
        if self._is_nested_jwt(headerobj):
            return self.verify(impl.decode(headerobj, rest))

        return True
