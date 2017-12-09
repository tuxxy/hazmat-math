from cryptography.hazmat.backends.openssl.ec import (
    _EllipticCurvePrivateKey, _EllipticCurvePublicKey
)


def _bignum_to_private_key(backend, group, bignum) -> _EllipticCurvePrivateKey:
    """
    Turns an OpenSSL BIGNUM into an EllipticCurvePrivateKey and returns it.
    """
    backend.openssl_assert(group != backend._ffi.NULL)
    backend.openssl_assert(bignum != backend._ffi.NULL)

    ec_key = backend._lib.EC_KEY_new()
    backend.openssl_assert(ec_key != backend._ffi.NULL)
    ec_key = backend._ffi.gc(ec_key, backend._lib.EC_KEY_free)

    res = backend._lib.EC_KEY_set_group(ec_key, group)
    backend.openssl_assert(res == 1)

    res = backend._lib.EC_KEY_set_private_key(ec_key, bignum)
    backend.openssl_assert(res == 1)

    # Get public key
    point = backend._lib.EC_POINT_new(group)
    backend.openssl_assert(point != backend._ffi.NULL)
    point = backend._ffi.gc(point, backend._lib.EC_POINT_free)

    with backend._tmp_bn_ctx() as bn_ctx:
        res = backend._lib.EC_POINT_mul(
            group, point, bignum, backend._ffi.NULL, backend._ffi.NULL, bn_ctx
        )
        backend.openssl_assert(res == 1)

        res = backend._lib.EC_KEY_set_public_key(ec_key, point)
        backend.openssl_assert(res == 1)

    evp_pkey = backend._ec_cdata_to_evp_pkey(ec_key)
    return _EllipticCurvePrivateKey(backend, ec_key, evp_pkey)


def _point_to_public_key(backend, group, point) -> _EllipticCurvePublicKey:
    """
    Converts an EC_POINT to an EllipticCurvePublicKey.
    """

    backend.openssl_assert(group != backend._ffi.NULL)
    backend.openssl_assert(point != backend._ffi.NULL)

    ec_key = backend._lib.EC_KEY_new()
    backend.openssl_assert(ec_key != backend._ffi.NULL)
    ec_key = backend._ffi.gc(ec_key, backend._lib.EC_KEY_free)

    res = backend._lib.EC_KEY_set_group(ec_key, group)
    backend.openssl_assert(res == 1)

    res = backend._lib.EC_KEY_set_public_key(ec_key, point)
    backend.openssl_assert(res == 1)

    evp_pkey = backend._ec_cdata_to_evp_pkey(ec_key)
    return _EllipticCurvePublicKey(backend, ec_key, evp_pkey)

