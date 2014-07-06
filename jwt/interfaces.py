# -*- coding: utf-8 -*-

from __future__ import absolute_import
import json


class Impl:

    def _json_encode(self, obj):
        assert isinstance(obj, dict)
        return json.dumps(obj)

    def _json_decode(self, encoded):
        assert isinstance(encoded, str)
        return json.loads(encoded)

    def is_supported(self, alg, enc=None):
        raise NotImplementedError

    def encode(self, headerobj, header, payload):
        raise NotImplementedError

    def decode(self, headerobj, rest):
        raise NotImplementedError

    def verify(self, headerobj, header, rest):
        raise NotImplementedError
