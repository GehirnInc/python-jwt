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

from jwt.jwa import (
    HS256,
    none,
)
from jwt.jwk import jwk_from_dict
from jwt.utils import b64decode

from .helper import load_testdata


class NoneTest(TestCase):

    def setUp(self):
        self.message = (
            b'eyJhbGciOiJub25lIn0'
            b'.'
            b'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt'
            b'cGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
        )

    def test_sign(self):
        signature = none.sign(self.message, None)
        self.assertEqual(signature, b'')

    def test_verify(self):
        self.assertTrue(none.verify(self.message, None, b''))


class HS256Test(TestCase):

    def setUp(self):
        self.key = jwk_from_dict(json.loads(load_testdata('oct.json', 'r')))
        self.signature = b64decode(
            'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
        )

        self.message = (
            b'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9'
            b'.'
            b'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt'
            b'cGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
        )

    def test_sign(self):
        signature = HS256.sign(self.message, self.key)
        self.assertEqual(signature, self.signature)

    def test_verify(self):
        self.assertTrue(HS256.verify(self.message, self.key, self.signature))
