# -*- coding: utf-8 -*-

from __future__ import absolute_import
import sys

from Crypto.PublicKey import RSA

from jwt.exceptions import (
    KeyNotFound,
    UnsupportedKeyType,
)
from jwt.utils import (
    b64_decode,
    b64_encode,
    base64_to_int,
    int_to_base64,
)


__all__ = ['JWK']

if sys.version_info[0] >= 3:
    long = lambda i: i


class JWK:

    REGISTRY = {}

    def __init__(self, impl):
        self.impl = impl

    @property
    def kty(self):
        return self.impl.kty

    @property
    def kid(self):
        return self.impl.kid

    @property
    def keyobj(self):
        return self.impl.keyobj

    def to_dict(self):
        return self.impl.to_dict()

    @classmethod
    def from_dict(cls, jwk):
        jwk = jwk.copy()
        try:
            impl = cls.REGISTRY[jwk['kty']]
        except KeyError:
            raise UnsupportedKeyType()
        else:
            del jwk['kty']

            return cls(impl.from_dict(jwk))

    @classmethod
    def register(cls, kty):
        def recv(impl):
            assert issubclass(impl, Impl)

            cls.REGISTRY[kty] = impl
            return impl

        return recv


class Impl(dict):

    def __init__(self, kty, params):
        self.kty = kty
        self.kid = params.get('kid')
        if 'kid' in params:
            del params['kid']
        self.update(params)

    def update(self, D):
        if len(set(D.keys()) & {'kty', 'kid'}) > 0:
            raise KeyError()

        return super(Impl, self).update(D)

    def to_dict(self):
        D = self.copy()
        D['kty'] = self.kty
        if self.kid:
            D['kid'] = self.kid

        return D

    @classmethod
    def from_dict(cls, D):
        D = D.copy()
        return cls(**D)

    @property
    def keyobj(self):
        raise NotImplementedError


@JWK.register('oct')
class OctKey(Impl):

    def __init__(self, k, **kwargs):
        self.k = k

        super(OctKey, self).__init__('oct', kwargs)

    def update(self, D):
        if 'k' in D:
            raise KeyError()

        return super(OctKey, self).update(D)

    def to_dict(self):
        D = super(OctKey, self).to_dict()
        D['k'] = b64_encode(self.k)

        return D

    @classmethod
    def from_dict(cls, D):
        D = D.copy()

        if 'k' in D:
            D['k'] = b64_decode(D['k'])

        return super(OctKey, cls).from_dict(D)

    @property
    def keyobj(self):
        return self.k


@JWK.register('RSA')
class RSAKey(Impl):

    def __init__(self, n, e, d=0, **kwargs):
        self.n = n
        self.e = e

        self.d = d

        super(RSAKey, self).__init__('RSA', kwargs)

    def update(self, D):
        if len(set(D.keys()) & {'n', 'e', 'd'}) > 0:
            raise KeyError()

        return super(RSAKey, self).update(D)

    def to_dict(self):
        D = super(RSAKey, self).to_dict()
        D['n'] = int_to_base64(self.n)
        D['e'] = int_to_base64(self.e)

        if self.d:
            D['d'] = int_to_base64(self.d)

        return D

    @classmethod
    def from_dict(cls, D):
        D = D.copy()
        for name in {'n', 'e', 'd'}:
            if name not in D:
                continue

            D[name] = base64_to_int(D[name])

        return super(RSAKey, cls).from_dict(D)

    @property
    def keyobj(self):
        if self.d:
            return RSA.construct((long(self.n), long(self.e), long(self.d)))

        return RSA.construct((long(self.n), long(self.e)))


class JWKSet(list):

    def append(self, value):
        if not isinstance(value, JWK):
            raise ValueError()

        try:
            self.get(value.kty, value.kid)
        except KeyNotFound:
            return super(JWKSet, self).append(value)
        else:
            raise ValueError('Key which is kty={kty} and kid={kid}'
                             'is already appended'.format(kty=value.kty,
                                                          kid=value.kid))

    def to_dict(self):
        return dict(keys=[jwk.to_dict() for jwk in self])

    @classmethod
    def from_dict(cls, D):
        inst = cls()

        for jwk in D['keys']:
            inst.append(JWK.from_dict(jwk))

        return inst

    def get(self, kty, kid=None, needs_private=False):
        for key in self:
            if key.kty != kty:
                continue

            if kid and key.kid != kid:
                continue

            if kty == 'RSA' and needs_private and not key.keyobj.has_private():
                continue

            return key

        raise KeyNotFound()

    def copy(self):
        inst = JWKSet()
        inst.extend(self)
        return inst

    def extend(self, L):
        assert isinstance(L, self.__class__)

        for key in L:
            self.append(key)
