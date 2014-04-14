# -*- coding: utf-8 -*-

import base64


def b64_encode(source):
    assert isinstance(source, bytes)
    return base64.urlsafe_b64encode(source).replace(b'=', b'')


def b64_decode(source):
    assert isinstance(source, bytes)
    source += b'=' * (4 - (len(source) % 4))
    return base64.urlsafe_b64decode(source)
