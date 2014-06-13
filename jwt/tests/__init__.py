# -*- coding: utf-8 -*-

import unittest


class ImplTest(unittest.TestCase):

    @property
    def target(self):
        from jwt.interfaces import Impl
        return Impl

    def test_is_supported(self):
        inst = self.target()

        with self.assertRaises(NotImplementedError):
            inst.is_supported('none')

    def test_encode(self):
        inst = self.target()

        with self.assertRaises(NotImplementedError):
            inst.encode({}, '', b'')

    def test_decode(self):
        inst = self.target()

        with self.assertRaises(NotImplementedError):
            inst.decode({}, '')

    def test_verify(self):
        inst = self.target()

        with self.assertRaises(NotImplementedError):
            inst.verify({}, '',  '')
