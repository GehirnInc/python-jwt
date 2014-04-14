# -*- coding: utf-8 -*-

import unittest

from .. import utils


class TestUtils(unittest.TestCase):

    def test_b64_encode(self):
        ret = b'{"iss":"joe",\r\n "exp":1300819380,\r\n ' \
            + b'"http://example.com/is_root":true}'
        self.assertEqual(
            utils.b64_encode(ret),
            b'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQog'
            b'Imh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ',
        )

    def test_b64_decode(self):
        ret = b'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQog' \
            + b'Imh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
        self.assertEqual(
            utils.b64_decode(ret),
            b'{"iss":"joe",\r\n "exp":1300819380,\r\n '
            b'"http://example.com/is_root":true}'
        )
