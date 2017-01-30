# -*- coding: utf-8 -*-

from jwt.utils import (
    b64encode,
    b64decode,
    uint_b64encode,
    uint_b64decode,
)


def test_b64encode():
    ret = (b'{"iss":"joe",\r\n "exp":1300819380,\r\n '
           b'"http://example.com/is_root":true}')
    expected = ('eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQog'
                'Imh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ')
    assert b64encode(ret) == expected


def test_b64decode():
    ret = ('eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQog'
           'Imh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ')
    expected = (b'{"iss":"joe",\r\n "exp":1300819380,\r\n '
                b'"http://example.com/is_root":true}')
    assert b64decode(ret) == expected


def test_uint_b64encode():
    assert uint_b64encode(65537) == 'AQAB'


def test_uint_b64decode():
    assert uint_b64decode('AQAB') == 65537
