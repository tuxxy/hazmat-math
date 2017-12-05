from hazmat_math.utils import _bignum_to_private_key

from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.backends.openssl import ec


def BN_MOD_MUL(priv_factor1, priv_factor2) -> ec._EllipticCurvePrivateKey:
    """
    Performs an OpenSSL BN_mod_mul on two EllipticCurvePrivateKeys and returns
    the result in an EllipticCurvePrivateKey.
    """
    group = backend._lib.EC_KEY_get0_group(priv_factor1._ec_key)
    backend.openssl_assert(group != backend._ffi.NULL)

    factor_a = backend._lib.EC_KEY_get0_private_key(priv_factor1._ec_key)
    backend.openssl_assert(factor_a != backend._ffi.NULL)

    factor_b = backend._lib.EC_KEY_get0_private_key(priv_factor2._ec_key)
    backend.openssl_assert(factor_b != backend._ffi.NULL)

    prod = backend._lib.BN_new()
    backend.openssl_assert(prod != backend._ffi.NULL)
    prod = backend._ffi.gc(prod, backend._lib.BN_free)

    order = backend._lib.BN_new()
    backend.openssl_assert(order != backend._ffi.NULL)
    order = backend._ffi.gc(order, backend._ffi.BN_free)

    with backend._tmp_bn_ctx() as bn_ctx:
        res = backend._lib.EC_GROUP_get_order(group, order, bn_ctx)
        backend.openssl_assert(res == 1)

        res = backend._lib.BN_mod_mul(
            prod, factor_a, factor_b, order, bn_ctx
        )
        backend.openssl_assert(res == 1)

    return _bignum_to_private_key(backend, group, prod)


def BN_DIV(priv_dividend, priv_divisor) -> ec._EllipticCurvePrivateKey:
    """
    Performs an OpenSSL BN_div on two EllipticCurvePrivateKeys and returns the
    result in an EllipticCurvePrivateKey.
    """
    group = backend._lib.EC_KEY_get0_group(priv_dividend._ec_key)
    backend.openssl_assert(group != backend._ffi.NULL)

    dividend = backend._lib.EC_KEY_get0_private_key(priv_dividend._ec_key)
    backend.openssl_assert(dividend != backend._ffi.NULL)

    divisor = backend._lib.EC_KEY_get0_private_key(priv_divisor._ec_key)
    backend.openssl_assert(divisor != backend._ffi.NULL)

    quotient = backend._lib.BN_new()
    backend.openssl_assert(quotient != backend._ffi.NULL)
    quotient = backend._ffi.gc(quotient, backend._lib.BN_free)

    with backend._tmp_bn_ctx() as bn_ctx:
        res = backend._lib.BN_div(
            quotient, backend._ffi.NULL, dividend, divisor, bn_ctx
        )
        backend.openssl_assert(res == 1)

    return _bignum_to_private_key(backend, group, quotient)


def BN_MOD_INVERSE(priv_a) -> ec._EllipticCurvePrivateKey:
    """
    Performs an OpenSSL BN_mod_inverse on an EllipticCurvePrivateKey and
    returns the result in an EllipticCurvePrivateKey.
    """
    group = backend._lib.EC_KEY_get0_group(priv_a._ec_key)
    backend.openssl_assert(group != backend._ffi.NULL)

    prv_a = backend._lib.EC_KEY_get0_private_key(priv_a._ec_key)
    backend.openssl_assert(prv_a != backend._ffi.NULL)

    order = backend._lib.BN_new()
    backend.openssl_assert(order != backend._ffi.NULL)
    order = backend._ffi.gc(order, backend._lib.BN_free)

    with backend._tmp_bn_ctx() as bn_ctx:
        res = backend._lib.EC_GROUP_get_order(group, order, bn_ctx)
        backend.openssl_assert(res == 1)

        inv = backend._lib.BN_mod_inverse(
            backend._ffi.NULL, prv_a, order, bn_ctx
        )
        backend.openssl_assert(inv != backend._ffi.NULL)
        inv = backend._ffi.gc(inv, backend._lib.BN_free)

    return _bignum_to_private_key(backend, group, inv)


def BN_MOD_ADD(priv_a, priv_b) -> ec._EllipticCurvePrivateKey:
    """
    Performs an OpenSSL BN_add on two EllipticCurvePrivateKeys and returns the
    result in an EllipticCurvePrivateKey.
    """
    group = backend._lib.EC_KEY_get0_group(priv_a._ec_key)
    backend.openssl_assert(group != backend._ffi.NULL)

    prv_a = backend._lib.EC_KEY_get0_private_key(priv_a._ec_key)
    backend.openssl_assert(prv_a != backend._ffi.NULL)

    prv_b = backend._lib.EC_KEY_get0_private_key(priv_b._ec_key)
    backend.openssl_assert(prv_b != backend._ffi.NULL)

    sum = backend._lib.BN_new()
    backend.openssl_assert(sum != backend._ffi.NULL)
    sum = backend._ffi.gc(sum, backend._lib.BN_free)

    order = backend._lib.BN_new()
    backend.openssl_assert(order != backend._ffi.NULL)
    order = backend._ffi.gc(order, backend._lib.BN_free)

    with backend._tmp_bn_ctx() as bn_ctx:
        res = backend._lib.BN_mod_add(
            sum, prv_a, prv_b, order, bn_ctx
        )
        backend.openssl_assert(res == 1)

    return _bignum_to_private_key(backend, group, sum)


def BN_MOD_SUB(priv_a, priv_b) -> ec._EllipticCurvePrivateKey:
    """
    Performs an OpenSSL BN_sub on two EllipticCurvePrivateKeys and returns the
    result in an EllipticCurvePrivateKey.
    """
    group = backend._lib.EC_KEY_get0_group(priv_a._ec_key)
    backend.openssl_assert(group != backend._ffi.NULL)

    prv_a = backend._lib.EC_KEY_get0_private_key(priv_a._ec_key)
    backend.openssl_assert(prv_a != backend._ffi.NULL)

    prv_b = backend._lib.EC_KEY_get0_private_key(priv_b._ec_key)
    backend.openssl_assert(prv_b != backend._ffi.NULL)

    diff = backend._lib.BN_new()
    backend.openssl_assert(diff != backend._ffi.NULL)
    diff = backend._ffi.gc(diff, backend._lib.BN_free)

    order = backend._lib.BN_new()
    backend.openssl_assert(order != backend._ffi.NULL)
    order = backend._ffi.gc(order, backend._lib.BN_free)

    with backend._tmp_bn_ctx() as bn_ctx:
        res = backend._lib.BN_mod_sub(
            diff, prv_a, prv_b, order, bn_ctx
        )
        backend.openssl_assert(res == 1)

    return _bignum_to_private_key(backend, group, diff)


def EC_POINT_MUL(pub_factor1, priv_factor2) -> ec._EllipticCurvePublicKey:
    """
    Performs an OpenSSL EC_POINT_mul on an EllipticCurvePublicKey with an
    EllipticCurvePrivateKey and returns the result in an EllipticCurvePublicKey.
    """
    pass


def EC_POINT_INVERT(pub_a) -> ec._EllipticCurvePublicKey:
    """
    Performs an OpenSSL EC_POINT_invert on an EllipticCurvePublicKey and returns
    the result in an EllipticCurvePublicKey.
    """
    pass


def EC_POINT_ADD(pub_a, pub_b) -> ec._EllipticCurvePublicKey:
    """
    Performs an OpenSSL EC_POINT_add on two EllipticCurvePublicKeys and returns
    the result in an EllipticCurvePublicKey.
    """
    pass


def EC_POINT_SUB(pub_a, pub_b) -> ec._EllipticCurvePublicKey:
    """
    Performs subtraction by adding an EllipticCurvePublicKey to the inverse of
    another EllipticCurvePublicKey and returns the result in an
    EllipticCurvePublicKey.
    """
    pass
