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
from datetime import datetime, timedelta, timezone

from jwt.utils import (
    b64encode,
    b64decode,
    get_time_from_int,
    get_time_from_str,
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


def test_get_time_from_str_with_str_wrong_format():
    assert get_time_from_str('this is not rfc3339') is None


def test_get_time_from_str_with_str_leap_second():
    # Not supported
    assert get_time_from_str('1990-12-31T23:59:60Z') is None


def test_get_time_from_str_with_str_with_float():
    expected = datetime(1985, 4, 12, 23, 20, 50, tzinfo=timezone.utc)
    assert get_time_from_str('1985-04-12T23:20:50.52Z') == expected


def test_get_time_from_str_with_str_timezone():
    expected = datetime(1996, 12, 19, 16, 39, 57, tzinfo=timezone.utc) + timedelta(hours=8)
    assert get_time_from_str('1996-12-19T16:39:57-08:00') == expected
    expected = datetime(1937, 1, 1, 12, 0, 27, tzinfo=timezone.utc) - timedelta(minutes=20)
    assert get_time_from_str('1937-01-01T12:00:27.87+00:20') == expected


def test_get_time_from_str_with_str_as_int():
    expected = datetime(2011, 3, 22, 18, 43, tzinfo=timezone.utc)
    assert get_time_from_str('1300819380') == expected


def test_get_time_from_int_with_int():
    expected = datetime(2011, 3, 22, 18, 43, tzinfo=timezone.utc)
    assert get_time_from_int(1300819380) == expected


def test_get_int_from_datetime_with_utc_timezone():
    param = datetime(2011, 3, 22, 18, 43, tzinfo=timezone.utc)
    assert get_int_from_datetime(param) == 1300819380


def test_get_int_from_datetime_with_timezone():
    param = datetime.strptime(
        '2011-03-22T19:43:00+0100',
        '%Y-%m-%dT%H:%M:%S%z'
    )
    assert get_int_from_datetime(param) == 1300819380
