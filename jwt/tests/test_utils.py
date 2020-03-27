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

from datetime import datetime, timezone

from jwt.utils import (
    b64encode,
    b64decode,
    get_time_from_int,
    get_int_from_datetime,
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


def test_get_time_from_int_with_int():
    expected = datetime(2011, 3, 22, 18, 43, tzinfo=timezone.utc)
    assert get_time_from_int(1300819380) == expected


def test_get_time_from_int_with_str():
    expected = datetime(2011, 3, 22, 18, 43, tzinfo=timezone.utc)
    assert get_time_from_int('1300819380') == expected


def test_get_int_from_datetime_with_utc_timezone():
    param = datetime(2011, 3, 22, 18, 43, tzinfo=timezone.utc)
    assert get_int_from_datetime(param) == 1300819380


def test_get_int_from_datetime_with_timezone():
    param = datetime.strptime(
        '2011-03-22T19:43:00+0100',
        '%Y-%m-%dT%H:%M:%S%z'
    )
    assert get_int_from_datetime(param) == 1300819380
