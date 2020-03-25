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
from typing import AbstractSet

from datetime import datetime, timezone

from jwt.utils import (
    get_time_from_int,
)
from .exceptions import (
    JWSEncodeError,
    JWSDecodeError,
    JWTEncodeError,
    JWTDecodeError,
)
from .jwk import AbstractJWKBase
from .jws import JWS


class JWT:

    def __init__(self):
        self._jws = JWS()

    def encode(self, payload: dict, key: AbstractJWKBase = None, alg='HS256',
               optional_headers: dict = None) -> str:
        try:
            message = json.dumps(payload).encode('utf-8')
        except ValueError as why:
            raise JWTEncodeError('payload must be able to encode in JSON')

        optional_headers = optional_headers and optional_headers.copy() or {}
        optional_headers['typ'] = 'JWT'
        try:
            return self._jws.encode(message, key, alg, optional_headers)
        except JWSEncodeError as why:
            raise JWTEncodeError('failed to encode to JWT') from why

    def decode(self, message: str, key: AbstractJWKBase = None,
               do_verify=True, algorithms: AbstractSet[str] = None,
               do_time_check: bool = True) -> dict:
        # utc now with timezone
        now = datetime.now(timezone.utc)
        try:
            message_bin = self._jws.decode(message, key, do_verify, algorithms)
        except JWSDecodeError as why:
            raise JWTDecodeError('failed to decode JWT') from why
        try:
            payload = json.loads(message_bin.decode('utf-8'))
            if 'exp' in payload:
                try:
                    exp = get_time_from_int(payload.get('exp'))
                    if do_time_check and (exp is None or now > exp):
                        raise JWTDecodeError("JWT Expired")
                except ValueError:
                    raise JWTDecodeError("Invalid Expired value")
            if 'nbf' in payload:
                try:
                    nbf = get_time_from_int(payload.get('nbf'))
                    if do_time_check and (nbf is None or now < nbf):
                        raise JWTDecodeError("JWT Not valid yet")
                except ValueError:
                    raise JWTDecodeError('Invalid "Not valid yet" value')

            return payload
        except ValueError as why:
            raise JWTDecodeError(
                'a payload of the JWT is not valid JSON') from why
