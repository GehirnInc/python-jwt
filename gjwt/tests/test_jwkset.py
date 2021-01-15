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

from jwt.jwkset import (
    JWKSet,
    jwk_from_dict,
)

from .helper import load_testdata


class JWKSetTest(TestCase):

    def setUp(self):
        self.inst = JWKSet()

        self.oct_json = json.loads(load_testdata('oct.json', 'r'))
        self.inst.append(jwk_from_dict(self.oct_json))

        self.rsa_json = json.loads(load_testdata('rsa_privkey_full.json', 'r'))
        self.rsa_pub_json = json.loads(load_testdata('rsa_pubkey.json', 'r'))
        self.inst.append(jwk_from_dict(self.rsa_json))

    def test_filter_keys(self):
        self.assertEqual(
            [key.to_dict(public_only=True) for key in self.inst.filter_keys()],
            [self.oct_json, self.rsa_pub_json])

        self.assertEqual(
            [key.to_dict(public_only=True)
             for key in self.inst.filter_keys(
                 kid='HMAC key used in JWS A.1 example')],
            [self.oct_json])

        self.assertEqual(
            [key.to_dict(public_only=True)
             for key in self.inst.filter_keys(kty='RSA')],
            [self.rsa_pub_json])

        self.assertEqual(
            [key.to_dict(public_only=True)
             for key in self.inst.filter_keys(
                 kid='HMAC key used in JWS A.1 example', kty='oct')],
            [self.oct_json])

    def test_to_dict(self):
        self.maxDiff = None
        self.assertEqual(
            self.inst.to_dict(public_only=True),
            {'keys': [self.oct_json, self.rsa_pub_json]})

    def test_from_dict(self):
        inst = JWKSet.from_dict({'keys': [self.oct_json, self.rsa_pub_json]})
        self.assertEqual(inst[0].to_dict(public_only=True), self.oct_json)
        self.assertEqual(inst[1].to_dict(public_only=True), self.rsa_pub_json)
