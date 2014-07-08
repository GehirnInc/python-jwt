# -*- coding: utf-8 -*-

from __future__ import absolute_import
import base64
import sys

if sys.version_info[0] == 3:
    ord = lambda i: i


def b64_encode(source):
    if not isinstance(source, bytes):
        source = source.encode('ascii')

    encoded = base64.urlsafe_b64encode(source).replace(b'=', b'')
    return str(encoded.decode('ascii'))


def b64_decode(source):
    if not isinstance(source, bytes):
        source = source.encode('ascii')

    source += b'=' * (4 - (len(source) % 4))
    return base64.urlsafe_b64decode(source)


def base64_to_int(source):
    if not isinstance(source, bytes):
        source = source.encode('ascii')

    result = 0
    for b in b64_decode(source):
        result = (result << 8) + ord(b)

    return result


def int_to_base64(source):
    result_reversed = []
    while source:
        source, remainder = divmod(source, 256)
        result_reversed.append(remainder)

    return b64_encode(bytes(bytearray(reversed(result_reversed))))
