from hazmat_math.utils import _bignum_to_private_key, _point_to_public_key

from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.backends.openssl.ec import (
    _EllipticCurvePrivateKey, _EllipticCurvePublicKey
)


def BN_MOD_MUL(priv_factor1, priv_factor2) -> _EllipticCurvePrivateKey:
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
    order = backend._ffi.gc(order, backend._lib.BN_free)

    with backend._tmp_bn_ctx() as bn_ctx:
        res = backend._lib.EC_GROUP_get_order(group, order, bn_ctx)
        backend.openssl_assert(res == 1)

        res = backend._lib.BN_mod_mul(
            prod, factor_a, factor_b, order, bn_ctx
        )
        backend.openssl_assert(res == 1)

    return _bignum_to_private_key(backend, group, prod)


def BN_DIV(priv_dividend, priv_divisor) -> _EllipticCurvePrivateKey:
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


def BN_MOD_INVERSE(priv_a) -> _EllipticCurvePrivateKey:
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


def BN_MOD_ADD(priv_a, priv_b) -> _EllipticCurvePrivateKey:
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
        res = backend._lib.EC_GROUP_get_order(group, order, bn_ctx)
        backend.openssl_assert(res == 1)

        res = backend._lib.BN_mod_add(
            sum, prv_a, prv_b, order, bn_ctx
        )
        backend.openssl_assert(res == 1)

    return _bignum_to_private_key(backend, group, sum)


def BN_MOD_SUB(priv_a, priv_b) -> _EllipticCurvePrivateKey:
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
        res = backend._lib.EC_GROUP_get_order(group, order, bn_ctx)
        backend.openssl_assert(res == 1)

        res = backend._lib.BN_mod_sub(
            diff, prv_a, prv_b, order, bn_ctx
        )
        backend.openssl_assert(res == 1)

    return _bignum_to_private_key(backend, group, diff)


def EC_POINT_MUL(pub_factor1, priv_factor2) -> _EllipticCurvePublicKey:
    """
    Performs an OpenSSL EC_POINT_mul on an EllipticCurvePublicKey with an
    EllipticCurvePrivateKey and returns the result in an EllipticCurvePublicKey.
    """
    group = backend._lib.EC_KEY_get0_group(pub_factor1._ec_key)
    backend.openssl_assert(group != backend._ffi.NULL)

    point_a = backend._lib.EC_KEY_get0_public_key(pub_factor1._ec_key)
    backend.openssl_assert(point_a != backend._ffi.NULL)

    priv_b = backend._lib.EC_KEY_get0_private_key(priv_factor2._ec_key)
    backend.openssl_assert(priv_b != backend._ffi.NULL)

    prod = backend._lib.EC_POINT_new(group)
    backend.openssl_assert(prod != backend._ffi.NULL)
    prod = backend._ffi.gc(prod, backend._lib.EC_POINT_free)

    with backend._tmp_bn_ctx() as bn_ctx:
        res = backend._lib.EC_POINT_mul(
            group, prod, backend._ffi.NULL, point_a, priv_b, bn_ctx
        )
        backend.openssl_assert(res == 1)

    return _point_to_public_key(backend, group, prod)


def EC_POINT_INVERT(pub_a) -> _EllipticCurvePublicKey:
    """
    Performs an OpenSSL EC_POINT_invert on an EllipticCurvePublicKey and returns
    the result in an EllipticCurvePublicKey.
    """
    group = backend._lib.EC_KEY_get0_group(pub_a._ec_key)
    backend.openssl_assert(group != backend._ffi.NULL)

    point_a = backend._lib.EC_KEY_get0_public_key(pub_a._ec_key)
    backend.openssl_assert(point_a != backend._ffi.NULL)

    inv = backend._lib.EC_POINT_dup(point_a, group)
    backend.openssl_assert(inv != backend._ffi.NULL)
    inv = backend._ffi.gc(inv, backend._lib.EC_POINT_free)

    with backend._tmp_bn_ctx() as bn_ctx:
        res = backend._lib.EC_POINT_invert(
            group, inv, bn_ctx
        )
        backend.openssl_assert(res == 1)

    return _point_to_public_key(backend, group, inv)


def EC_POINT_ADD(pub_a, pub_b) -> _EllipticCurvePublicKey:
    """
    Performs an OpenSSL EC_POINT_add on two EllipticCurvePublicKeys and returns
    the result in an EllipticCurvePublicKey.
    """
    group_a = backend._lib.EC_KEY_get0_group(pub_a._ec_key)
    backend.openssl_assert(group_a != backend._ffi.NULL)

    group_b = backend._lib.EC_KEY_get0_group(pub_b._ec_key)
    backend.openssl_assert(group_b != backend._ffi.NULL)

    point_a = backend._lib.EC_KEY_get0_public_key(pub_a._ec_key)
    backend.openssl_assert(point_a != backend._ffi.NULL)

    point_b = backend._lib.EC_KEY_get0_public_key(pub_b._ec_key)
    backend.openssl_assert(point_b != backend._ffi.NULL)

    sum = backend._lib.EC_POINT_new(group_a)
    backend.openssl_assert(sum != backend._ffi.NULL)
    sum = backend._ffi.gc(sum, backend._lib.EC_POINT_free)

    with backend._tmp_bn_ctx() as bn_ctx:
        curve_a = backend._lib.EC_GROUP_get_curve_name(group_a)
        curve_b = backend._lib.EC_GROUP_get_curve_name(group_b)
        backend.openssl_assert(curve_a == curve_b)

        res = backend._lib.EC_POINT_add(
            group_a, sum, point_a, point_b, bn_ctx
        )
        backend.openssl_assert(res == 1)

    return _point_to_public_key(backend, group_a, sum)


def EC_POINT_SUB(pub_a, pub_b) -> _EllipticCurvePublicKey:
    """
    Performs subtraction by adding an EllipticCurvePublicKey to the inverse of
    another EllipticCurvePublicKey and returns the result in an
    EllipticCurvePublicKey.
    """
    pub_b = EC_POINT_INVERT(pub_b)

    return EC_POINT_ADD(pub_a, pub_b)


def CURVE_GET_GENERATOR(curve) -> _EllipticCurvePublicKey:
    """
    Returns the generator point of the curve provided.
    This returns it as a public key to use in the above operations, if needed.
    """
    curve_nid = backend._elliptic_curve_to_nid(curve)

    group = backend._lib.EC_GROUP_new_by_curve_name(curve_nid)
    backend.openssl_assert(group != backend._ffi.NULL)

    gen_point = backend._lib.EC_POINT_new(group)
    backend.openssl_assert(gen_point != backend._ffi.NULL)
    gen_point = backend._ffi.gc(gen_point, backend._lib.EC_POINT_free)

    generator = backend._lib.EC_GROUP_get0_generator(group)
    backend.openssl_assert(generator != backend._ffi.NULL)

    res = backend._lib.EC_POINT_copy(
        gen_point, generator
    )
    backend.openssl_assert(res == 1)

    return _point_to_public_key(backend, group, generator)


def CURVE_GET_ORDER(curve) -> _EllipticCurvePrivateKey:
    """
    Returns the order of the curve provided.
    This returns it as a private key to use in the above operations, if needed.
    """
    curve_nid = backend._elliptic_curve_to_nid(curve)

    group = backend._lib.EC_GROUP_new_by_curve_name(curve_nid)
    backend.openssl_assert(group != backend._ffi.NULL)

    order = backend._lib.BN_new()
    backend.openssl_assert(order != backend._ffi.NULL)
    order = backend._ffi.gc(order, backend._lib.BN_free)

    with backend._tmp_bn_ctx() as bn_ctx:
        res = backend._lib.EC_GROUP_get_order(group, order, bn_ctx)
        backend.openssl_assert(res == 1)

    return _bignum_to_private_key(backend, group, order)
