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
from datetime import timedelta, datetime, timezone
from unittest import TestCase

from freezegun import freeze_time

from jwt.exceptions import JWTDecodeError
from jwt.jwk import jwk_from_dict
from jwt.jwt import JWT
from jwt.utils import get_int_from_datetime

from .helper import load_testdata


class JWTTest(TestCase):

    def setUp(self):
        self.inst = JWT()
        self.key = jwk_from_dict(
            json.loads(load_testdata('oct.json', 'r')))

        self.message = {
            'iss': 'joe',
            'exp': 1300819380,
            'http://example.com/is_root': True,
        }

        self.compact_jws = (
            'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9'
            '.'
            'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt'
            'cGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
            '.'
            'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
        )

    @freeze_time("2011-03-22 18:00:00", tz_offset=0)
    def test_decode(self):
        message = self.inst.decode(self.compact_jws, self.key)
        self.assertEqual(message, self.message)

    def test_decode_with_do_time_check_disabled(self):
        message = self.inst.decode(
            self.compact_jws, self.key, do_time_check=False)
        self.assertEqual(message, self.message)

    def test_expiration(self):
        self.assertRaisesRegex(
            JWTDecodeError, 'JWT Expired',
            self.inst.decode, self.compact_jws, self.key
        )

    def test_no_before_used_before(self):
        compact_jws = self.inst.encode({
            'nbf': get_int_from_datetime(
                datetime.now(timezone.utc) + timedelta(hours=1))
        }, self.key)
        self.assertRaisesRegex(
            JWTDecodeError, 'JWT Not valid yet',
            self.inst.decode, compact_jws, self.key
        )

    def test_no_before_used_after(self):
        message = {
            'nbf': get_int_from_datetime(
                datetime.now(timezone.utc) - timedelta(hours=1))
        }
        compact_jws = self.inst.encode(message, self.key)
        self.assertEqual(self.inst.decode(compact_jws, self.key), message)
