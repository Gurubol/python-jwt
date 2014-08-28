# -*- coding: utf-8 -*-

from __future__ import absolute_import
import json

from jwt.exceptions import (
    MalformedJWT,
    UnsupportedAlgorithm,
)
from jwt.interfaces import Impl
from jwt.jws import JWS
from jwt.utils import (
    b64_decode,
    b64_encode,
)


class JWT(Impl):

    def __init__(self, keys):
        self.keys = keys

        self.jws = JWS(keys)
        self.jwe = None

    def _get_impl(self, alg):
        if self.jws.is_supported(alg):
            return self.jws
        elif self.jwe and self.jwe.is_supported(alg):
            return self.jwe

        raise UnsupportedAlgorithm(alg)

    def sign(self, alg, message, kid=None):
        return self.jws.sign(alg, message, kid)

    def verify(self, jwt):
        try:
            if not isinstance(jwt, bytes):
                jwt = jwt.encode('ascii')
        except UnicodeEncodeError:
            raise MalformedJWT('JWT must be encoded in ascii')

        encoded_header, rest = jwt.split(b'.', 1)
        headerobj = json.loads(b64_decode(encoded_header).decode('ascii'))
        impl = self._get_impl(headerobj['alg'])

        if headerobj.get('cty') == 'JWT':
            jwt = impl.decode(headerobj, rest)
            return self.verify(jwt)

        return impl.verify(headerobj, encoded_header, rest)

    def encode(self, headerobj, payload):
        assert isinstance(headerobj, dict)
        if not isinstance(payload, bytes):
            raise TypeError('payload must be a bytes')

        try:
            impl = self._get_impl(headerobj['alg'])
        except KeyError:
            raise MalformedJWT('\'alg\' is required')

        encoded_header = b64_encode(json.dumps(headerobj).encode('ascii'))
        return '.'.join((
            encoded_header,
            impl.encode(headerobj, encoded_header, payload)
        ))

    def decode(self, jwt):
        try:
            if not isinstance(jwt, bytes):
                jwt = jwt.encode('ascii')

            encoded_header, rest = jwt.split(b'.', 1)
            headerobj = json.loads(b64_decode(encoded_header).decode('ascii'))
        except (UnicodeEncodeError, UnicodeDecodeError):
            raise MalformedJWT('JWT must be encoded in ascii')

        impl = self._get_impl(headerobj['alg'])
        if not impl.verify(headerobj, encoded_header, rest):
            raise MalformedJWT()

        payload = impl.decode(headerobj, rest)
        if headerobj.get('cty') == 'JWT':
            return self.decode(payload)

        return payload
