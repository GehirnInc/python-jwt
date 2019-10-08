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
import re
from base64 import (
    urlsafe_b64encode,
    urlsafe_b64decode,
)

from datetime import datetime, timezone
from typing import Union


RE_RFC3339 = re.compile(
    '(?P<datetime>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:(?P<leap>\d{2}))'
    '(?P<float>\.\d+)?'
    '(Z|(?P<timezone>(?P<symbol>[+\-])(?P<hour>\d{2}):(?P<minute>\d{2})))?'
)


def b64encode(s: bytes) -> str:
    s_bin = urlsafe_b64encode(s)
    s_bin = s_bin.replace(b'=', b'')
    return s_bin.decode('ascii')


def b64decode(s: str) -> bytes:
    s_bin = s.encode('ascii')
    s_bin += b'=' * (4 - len(s_bin) % 4)
    return urlsafe_b64decode(s_bin)


def uint_b64encode(value: int) -> str:
    length = 1
    rem = value >> 8
    while rem:
        length += 1
        rem >>= 8

    uint_bin = value.to_bytes(length, 'big', signed=False)
    return b64encode(uint_bin)


def uint_b64decode(uint_b64: str) -> int:
    uint_bin = b64decode(uint_b64)

    value = 0
    for b in uint_bin:
        value <<= 8
        value += int(b)
    return value


def get_time(value: Union[str, int, datetime]) -> Union[int, datetime, None]:
    """
    :param value: The value of time to convert
                  If is str or int datetime or None will be returned
                  If is datetime int will be returned
    :return: None if the string is not valid
             datetime if is valid str or int
             int if value is datetime
    """
    returned = None
    if isinstance(value, str):
        is_rfc3339 = RE_RFC3339.match(value)
        if is_rfc3339:
            rfc3339 = is_rfc3339.groupdict()
            tz = '+0000'
            try:
                if rfc3339.get('timezone'):
                    tz = '{}{}{}'.format(
                        rfc3339.get('symbol'),
                        rfc3339.get('hour'),
                        rfc3339.get('minute'),
                    )
                returned = datetime.strptime(
                    rfc3339.get('datetime')+tz,
                    '%Y-%m-%dT%H:%M:%S%z'
                ).astimezone(timezone.utc)
            except ValueError:
                pass
        else:
            try:
                value = int(value)
            except ValueError:
                pass

    if isinstance(value, int):
        returned = datetime.utcfromtimestamp(value)
        # Add the UTC timezone
        returned = datetime.strptime(
            returned.strftime('%Y-%m-%dT%H:%M:%S') + '+0000',
            '%Y-%m-%dT%H:%M:%S%z'
        )

    elif isinstance(value, datetime):
        returned = int(value.timestamp())

    return returned
