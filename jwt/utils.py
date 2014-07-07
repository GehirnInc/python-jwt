# -*- coding: utf-8 -*-

from __future__ import absolute_import
import base64


def b64_encode(source):
    source = str(source)

    return base64.urlsafe_b64encode(source).replace(b'=', b'')


def b64_decode(source):
    source = str(source)

    source += b'=' * (4 - (len(source) % 4))
    return base64.urlsafe_b64decode(source)


def base64_to_int(source):
    if isinstance(source, str):
        source = source.encode('ascii')

    result = 0
    for b in b64_decode(source):
        result = (result << 8) + ord(b)

    return result


def int_to_base64(source):
    result_reversed = []
    while source:
        source, remainder = divmod(source, 256)
        result_reversed.append(chr(remainder))

    return b64_encode(''.join(reversed(result_reversed)))
