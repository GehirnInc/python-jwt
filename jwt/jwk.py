# -*- coding: utf-8 -*-
#
# Copyright 2017 Gehirn Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import hmac
from abc import (
    ABC,
    abstractmethod,
)
from typing import (
    Any,
    Callable,
    Mapping,
    Union,
    Optional
)
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import (
    rsa_crt_dmp1,
    rsa_crt_dmq1,
    rsa_crt_iqmp,
    rsa_recover_prime_factors,
    RSAPrivateKey,
    RSAPrivateNumbers,
    RSAPublicKey,
    RSAPublicNumbers,
)
import cryptography.hazmat.primitives.serialization as serialization_module

from cryptography.hazmat.primitives.hashes import HashAlgorithm

from .exceptions import (
    MalformedJWKError,
    UnsupportedKeyTypeError,
)
from .utils import (
    b64encode,
    b64decode,
    uint_b64encode,
    uint_b64decode,
)


class AbstractJWKBase(ABC):

    @abstractmethod
    def get_kty(self):
        pass  # pragma: no cover

    @abstractmethod
    def get_kid(self):
        pass  # pragma: no cover

    @abstractmethod
    def is_sign_key(self) -> bool:
        pass  # pragma: no cover

    @abstractmethod
    def sign(self, message: bytes, **options) -> bytes:
        pass  # pragma: no cover

    @abstractmethod
    def verify(self, message: bytes, signature: bytes, **options) -> bool:
        pass  # pragma: no cover

    @abstractmethod
    def to_dict(self, public_only=True):
        pass  # pragma: no cover

    @classmethod
    @abstractmethod
    def from_dict(cls, dct):
        pass  # pragma: no cover


class OctetJWK(AbstractJWKBase):

    def __init__(self, key: bytes, kid=None, **options) -> None:
        super(AbstractJWKBase, self).__init__()
        self.key = key
        self.kid = kid

        optnames = {'use', 'key_ops', 'alg', 'x5u', 'x5c', 'x5t', 'x5t#s256'}
        self.options = {k: v for k, v in options.items() if k in optnames}

    def get_kty(self):
        return 'oct'

    def get_kid(self):
        return self.kid

    def is_sign_key(self) -> bool:
        return True

    def _get_signer(self, options) -> Callable[[bytes, bytes], bytes]:
        return options['signer']

    def sign(self, message: bytes, **options) -> bytes:
        signer = self._get_signer(options)
        return signer(message, self.key)

    def verify(self, message: bytes, signature: bytes, **options) -> bool:
        signer = self._get_signer(options)
        return hmac.compare_digest(signature, signer(message, self.key))

    def to_dict(self, public_only=True):
        dct = {
            'kty': 'oct',
            'k': b64encode(self.key),
        }
        dct.update(self.options)
        if self.kid:
            dct['kid'] = self.kid
        return dct

    @classmethod
    def from_dict(cls, dct):
        try:
            return cls(b64decode(dct['k']), **dct)
        except KeyError as why:
            raise MalformedJWKError('k is required') from why


class RSAJWK(AbstractJWKBase):
    """
    https://tools.ietf.org/html/rfc7518.html#section-6.3.1
    """

    def __init__(self, keyobj: Union[RSAPrivateKey, RSAPublicKey],
                 **options) -> None:
        super(AbstractJWKBase, self).__init__()
        self.keyobj = keyobj

        optnames = {'use', 'key_ops', 'alg', 'kid',
                    'x5u', 'x5c', 'x5t', 'x5t#s256', }
        self.options = {k: v for k, v in options.items() if k in optnames}

    def is_sign_key(self) -> bool:
        return isinstance(self.keyobj, RSAPrivateKey)

    def _get_hash_fun(self, options) -> Callable[[], HashAlgorithm]:
        return options['hash_fun']

    def _get_padding(self, options) -> padding.AsymmetricPadding:
        return options['padding']

    def sign(self, message: bytes, **options) -> bytes:
        hash_fun = self._get_hash_fun(options)
        _padding = self._get_padding(options)
        return self.keyobj.sign(message, _padding, hash_fun())

    def verify(self, message: bytes, signature: bytes, **options) -> bool:
        hash_fun = self._get_hash_fun(options)
        _padding = self._get_padding(options)
        if self.is_sign_key():
            pubkey = self.keyobj.public_key()
        else:
            pubkey = self.keyobj
        try:
            pubkey.verify(signature, message, _padding, hash_fun())
            return True
        except InvalidSignature:
            return False

    def get_kty(self):
        return 'RSA'

    def get_kid(self):
        return self.options.get('kid')

    def to_dict(self, public_only=True):
        dct = {
            'kty': 'RSA',
        }
        dct.update(self.options)

        if isinstance(self.keyobj, RSAPrivateKey):
            priv_numbers = self.keyobj.private_numbers()
            pub_numbers = priv_numbers.public_numbers
            dct.update({
                'e': uint_b64encode(pub_numbers.e),
                'n': uint_b64encode(pub_numbers.n),
            })
            if not public_only:
                dct.update({
                    'e': uint_b64encode(pub_numbers.e),
                    'n': uint_b64encode(pub_numbers.n),
                    'd': uint_b64encode(priv_numbers.d),
                    'p': uint_b64encode(priv_numbers.p),
                    'q': uint_b64encode(priv_numbers.q),
                    'dp': uint_b64encode(priv_numbers.dmp1),
                    'dq': uint_b64encode(priv_numbers.dmq1),
                    'qi': uint_b64encode(priv_numbers.iqmp),
                })
            return dct
        pub_numbers = self.keyobj.public_numbers()
        dct.update({
            'e': uint_b64encode(pub_numbers.e),
            'n': uint_b64encode(pub_numbers.n),
        })
        return dct

    @classmethod
    def from_dict(cls, dct):
        if 'oth' in dct:
            raise UnsupportedKeyTypeError(
                'RSA keys with multiples primes are not supported')

        try:
            e = uint_b64decode(dct['e'])
            n = uint_b64decode(dct['n'])
        except KeyError as why:
            raise MalformedJWKError('e and n are required') from why
        pub_numbers = RSAPublicNumbers(e, n)
        if 'd' not in dct:
            return cls(
                pub_numbers.public_key(backend=default_backend()), **dct)
        d = uint_b64decode(dct['d'])

        privparams = {'p', 'q', 'dp', 'dq', 'qi'}
        product = set(dct.keys()) & privparams
        if len(product) == 0:
            p, q = rsa_recover_prime_factors(n, e, d)
            priv_numbers = RSAPrivateNumbers(
                d=d,
                p=p,
                q=q,
                dmp1=rsa_crt_dmp1(d, p),
                dmq1=rsa_crt_dmq1(d, q),
                iqmp=rsa_crt_iqmp(p, q),
                public_numbers=pub_numbers)
        elif product == privparams:
            priv_numbers = RSAPrivateNumbers(
                d=d,
                p=uint_b64decode(dct['p']),
                q=uint_b64decode(dct['q']),
                dmp1=uint_b64decode(dct['dp']),
                dmq1=uint_b64decode(dct['dq']),
                iqmp=uint_b64decode(dct['qi']),
                public_numbers=pub_numbers)
        else:
            # If the producer includes any of the other private key parameters,
            # then all of the others MUST be present, with the exception of
            # "oth", which MUST only be present when more than two prime
            # factors were used.
            raise MalformedJWKError(
                'p, q, dp, dq, qi MUST be present or'
                'all of them MUST be absent')
        return cls(priv_numbers.private_key(backend=default_backend()), **dct)


def supported_key_types():
    return {
        'oct': OctetJWK,
        'RSA': RSAJWK,
    }


def jwk_from_dict(dct: Mapping[str, Any]) -> AbstractJWKBase:
    if not isinstance(dct, dict):  # pragma: no cover
        raise TypeError('dct must be a dict')
    if 'kty' not in dct:
        raise MalformedJWKError('kty MUST be present')

    supported = supported_key_types()
    kty = dct['kty']
    if kty not in supported:
        raise UnsupportedKeyTypeError('unsupported key type: {}'.format(kty))
    return supported[kty].from_dict(dct)


def jwk_from_bytes_argument_conversion(func):
    if 'private' in func.__name__:
        kind = 'private'
    elif 'public' in func.__name__:
        kind = 'public'
    else:
        raise Exception("the wrapped function must have either public"
                        " or private in it's name")

    def wrapper(content, **kwargs):
        # content is the only positional argument allowed
        # the function you wrap must use kwargs-only arguments PEP3102
        if not isinstance(content, bytes):  # pragma: no cover
            raise TypeError(
                'content must be bytes, it is {}'.format(type(content)))
        load_function = f'serializer_load_function_{kind}'
        if kwargs.get(load_function) is None:
            raise Exception(f'{load_function} is not Optional')
        # now convert it to a Callable if it's a string
        if isinstance(kwargs.get(load_function), str):
            kwargs[load_function] = getattr(
                serialization_module,
                kwargs.get(load_function),
            )

        if kwargs.get('backend') is None:
            kwargs['backend'] = default_backend()

        return func(content, **kwargs)
    return wrapper


@jwk_from_bytes_argument_conversion
def jwk_from_private_bytes(
    content: bytes,
    *,
    serializer_load_function_private:
        Union[str, Callable[[bytes, Optional[str], object], object]] = None,
    password: Optional[str] = None,
    backend: Optional[object] = None,
) -> Optional[AbstractJWKBase]:
    """This function is meant to be called from jwk_from_bytes"""
    try:
        privkey = serializer_load_function_private(
            content,
            password=password,
            backend=backend,
        )
        if isinstance(privkey, RSAPrivateKey):
            return RSAJWK(privkey)
        raise UnsupportedKeyTypeError('unsupported key type')
    except ValueError:
        return None


@jwk_from_bytes_argument_conversion
def jwk_from_public_bytes(
    content: bytes,
    *,
    serializer_load_function_public:
        Union[str, Callable[[bytes, Optional[str], object], object]] = None,
    backend: Optional[object] = None,
) -> Optional[AbstractJWKBase]:
    """This function is meant to be called from jwk_from_bytes"""
    try:
        pubkey = serializer_load_function_public(
            content,
            backend=backend,
        )
        if isinstance(pubkey, RSAPublicKey):
            return RSAJWK(pubkey)
        raise UnsupportedKeyTypeError(
            'unsupported key type')  # pragma: no cover
    except ValueError as why:
        raise UnsupportedKeyTypeError('could not deserialize') from why


def jwk_from_bytes(
    content: bytes,
    *,
    serializer_load_function_private:
        Union[str, Callable[[bytes, Optional[str], object], object]] = None,
    serializer_load_function_public:
        Union[str, Callable[[bytes, Optional[str], object], object]] = None,
    private_password: Optional[str] = None,
    backend: Optional[object] = None,
) -> AbstractJWKBase:
    privkey = jwk_from_private_bytes(
        content,
        serializer_load_function_private=serializer_load_function_private,
        password=private_password,
        backend=backend,
    )
    if privkey is not None:
        return privkey

    return jwk_from_public_bytes(
        content,
        serializer_load_function_public=serializer_load_function_public,
        backend=backend,
    )


def jwk_from_pem(
    pem_content: bytes,
    private_password: Optional[str] = None,
) -> AbstractJWKBase:
    return jwk_from_bytes(
        pem_content,
        serializer_load_function_private='load_pem_private_key',
        serializer_load_function_public='load_pem_public_key',
        private_password=private_password,
        backend=None,
    )


def jwk_from_der(
    der_content: bytes,
    private_password: Optional[str] = None,
) -> AbstractJWKBase:
    return jwk_from_bytes(
        der_content,
        serializer_load_function_private='load_der_private_key',
        serializer_load_function_public='load_der_public_key',
        private_password=private_password,
        backend=None,
    )
