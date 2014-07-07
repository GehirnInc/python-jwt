# -*- coding: utf-8 -*-

JWTException = type('JWTException', (Exception, ), {})
MalformedJWT = type('MalformedJWT', (JWTException, ), {})
KeyNotFound = type('KeyNotFound', (JWTException, ), {})
InvalidKeyType = type('InvalidKeyType', (JWTException, ), {})
UnsupportedKeyType = type('UnsupportedKeyType', (JWTException, ), {})
UnsupportedAlgorithm = type('UnsupportedAlgorithm', (JWTException, ), {})
