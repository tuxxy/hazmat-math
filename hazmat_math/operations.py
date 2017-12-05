from cryptography.hazmat.primitives.asymmetric import ec


def BN_MOD_MUL(priv_factor1, priv_factor2) -> ec.EllipticCurvePrivateKey:
    """
    Performs an OpenSSL BN_mod_mul on two EllipticCurvePrivateKeys and returns
    the result in an EllipticCurvePrivateKey.
    """
    pass


def BN_DIV(priv_dividend, priv_divisor) -> ec.EllipticCurvePrivateKey:
    """
    Performs an OpenSSL BN_div on two EllipticCurvePrivateKeys and returns the
    result in an EllipticCurvePrivateKey.
    """
    pass


def BN_MOD_INVERSE(priv_a) -> ec.EllipticCurvePrivateKey:
    """
    Performs an OpenSSL BN_mod_inverse on an EllipticCurvePrivateKey and
    returns the result in an EllipticCurvePrivateKey.
    """
    pass


def BN_MOD_ADD(priv_a, priv_b) -> ec.EllipticCurvePrivateKey:
    """
    Performs an OpenSSL BN_add on two EllipticCurvePrivateKeys and returns the
    result in an EllipticCurvePrivateKey.
    """
    pass


def BN_MOD_SUB(priv_a, priv_b) -> ec.EllipticCurvePrivateKey:
    """
    Performs an OpenSSL BN_sub on two EllipticCurvePrivateKeys and returns the
    result in an EllipticCurvePrivateKey.
    """
    pass


def EC_POINT_MUL(pub_factor1, priv_factor2) -> ec.EllipticCurvePublicKey:
    """
    Performs an OpenSSL EC_POINT_mul on an EllipticCurvePublicKey with an
    EllipticCurvePrivateKey and returns the result in an EllipticCurvePublicKey.
    """
    pass


def EC_POINT_INVERT(pub_a) -> ec.EllipticCurvePublicKey:
    """
    Performs an OpenSSL EC_POINT_invert on an EllipticCurvePublicKey and returns
    the result in an EllipticCurvePublicKey.
    """
    pass


def EC_POINT_ADD(pub_a, pub_b) -> ec.EllipticCurvePublicKey:
    """
    Performs an OpenSSL EC_POINT_add on two EllipticCurvePublicKeys and returns
    the result in an EllipticCurvePublicKey.
    """
    pass


def EC_POINT_SUB(pub_a, pub_b) -> ec.EllipticCurvePublicKey:
    """
    Performs subtraction by adding an EllipticCurvePublicKey to the inverse of
    another EllipticCurvePublicKey and returns the result in an
    EllipticCurvePublicKey.
    """
    pass
