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
from unittest import TestCase

from freezegun import freeze_time

from jwt.jws import JWS
from jwt.jwk import jwk_from_dict

from .helper import load_testdata


class JWSTest(TestCase):

    def setUp(self):
        self.inst = JWS()
        self.key = jwk_from_dict(
            json.loads(load_testdata('rsa_privkey.json', 'r')))
        self.pubkey = jwk_from_dict(
            json.loads(load_testdata('rsa_pubkey.json', 'r')))

        self.message = (
            b'{"iss":"joe",\r\n'
            b' "exp":1300819380,\r\n'
            b' "http://example.com/is_root":true}'
        )
        self.compact_jws = (
            'eyJhbGciOiJSUzI1NiJ9'
            '.'
            'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt'
            'cGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
            '.'
            'cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7'
            'AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4'
            'BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K'
            '0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv'
            'hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB'
            'p0igcN_IoypGlUPQGe77Rw'
        )

    def test_encode(self):
        compact_jws = self.inst.encode(self.message, self.key, alg='RS256')
        self.assertEqual(compact_jws, self.compact_jws)

    def test_decode(self):
        message = self.inst.decode(self.compact_jws, self.key)
        self.assertEqual(message, self.message)

    @freeze_time("2011-03-22 18:00:00", tz_offset=0)
    def test_decode_pubkey(self):
        message = self.inst.decode(self.compact_jws, self.pubkey)
        self.assertEqual(message, self.message)
