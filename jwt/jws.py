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

import json
from typing import Tuple

from .exceptions import (
    JWSEncodeError,
    JWSDecodeError,
)
from .jwa import (
    supported_signing_algorithms,
    AbstractSigningAlgorithm,
)
from .jwk import AbstractJWKBase
from .utils import (
    b64encode,
    b64decode,
)

__all__ = ['JWS']


class JWS:

    def __init__(self) -> None:
        self._supported_algs = supported_signing_algorithms()

    def _retrieve_alg(self, alg: str) -> AbstractSigningAlgorithm:
        return self._supported_algs[alg]

    def encode(self, message: bytes, key: AbstractJWKBase = None, alg='HS256',
               optional_headers: dict = None) -> str:
        if alg not in self._supported_algs:
            raise JWSEncodeError('unsupported algorithm: {}'.format(alg))
        alg_impl = self._retrieve_alg(alg)

        header = {}
        header_b64 = b64encode(json.dumps(header).encode('ascii'))
        message_b64 = b64encode(message)
        signing_message = header_b64 + b'.' + message_b64

        signature = alg_impl.sign(signing_message, key)
        signature_b64 = b64encode(signature)

        return signing_message + b'.' + signature_b64

    def _decode_segments(self, message: bytes, key: AbstractJWKBase = None
                         ) -> Tuple[dict, bytes, bytes, bytes]:
        try:
            signing_message, signature_b64 = message.rsplit('.', 1)
            header_b64, message_b64 = signing_message.split('.')
        except ValueError:
            raise JWSDecodeError('malformed JWS payload')

        header = json.loads(b64decode(header_b64))
        message = b64decode(message_b64)
        signature = b64decode(message_b64)
        return header, message, signature, signing_message

    def decode(self, message: str, key: AbstractJWKBase = None,
               do_verify=True) -> bytes:
        header, message, signature, signing_message =\
                self._decode_segments(message, key)

        alg_impl = self._retrieve_alg(header['alg'])
        if do_verify and not alg_impl.verify(signing_message, key, signature):
            raise JWSDecodeError('JWS passed could not be validated')

        return message
