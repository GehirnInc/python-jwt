# -*- coding: utf-8 -*-

import base64


def b64_encode(source):
    if isinstance(source, str):
        source = source.encode('ascii')

    return base64.urlsafe_b64encode(source).replace(b'=', b'').decode('ascii')


def b64_decode(source):
    if isinstance(source, str):
        source = source.encode('ascii')

    source += b'=' * (4 - (len(source) % 4))
    return base64.urlsafe_b64decode(source)


def base64_to_int(source):
    if isinstance(source, str):
        source = source.encode('ascii')

    result = 0
    for b in b64_decode(source):
        result = (result << 8) + b

    return result


def int_to_base64(source):
    result_reversed = []
    while source:
        source, remainder = divmod(source, 256)
        result_reversed.append(remainder)

    return b64_encode(bytes(reversed(result_reversed)))
