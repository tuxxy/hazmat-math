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
