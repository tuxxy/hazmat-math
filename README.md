# hazmat-math
Hazmat ECC arithmetic for Cryptography.io

Hazmat math implements some basic ECC arithmetic for use with Cryptography.io objects using the OpenSSL backend.
Specifically, `_EllipticCurvePrivateKey` and `_EllipticCurvePublicKey`.

Any operations with `EC_POINT` will return an `_EllipticCurvePublicKey` and any operations with `BN` will return an `_EllipticCurvePrivateKey`.

# Usage:
```
from cryptography.hazmat.backends import default_backend()
from cryptography.hazmat.primitives.asymmetric import ec

from hazmat_math import operations as ops


priv_a = ec.generate_private_keys(ec.SECP256K1(), default_backend())
priv_b = ec.generate_private_keys(ec.SECP256K1(), default_backend())

pub_a = priv_a.public_key()
pub_b = priv_b.public_key()

# Multiplication
priv_c = ops.BN_MOD_MUL(priv_a, priv_b)
pub_c = ops.EC_POINT_MUL(pub_a, priv_a)

# Division
priv_c = ops.BN_DIV(priv_a, priv_b)

# Inversion
inv_a_priv = ops.BN_MOD_INVERSE(priv_a)
inv_a_pub = ops.EC_POINT_INVERT(pub_a)

# Addition
priv_c = ops.BN_MOD_ADD(priv_a, priv_b)
pub_c = ops.EC_POINT_ADD(pub_a, pub_b)

# Subtraction
priv_c = ops.BN_MOD_SUB(priv_a, priv_b)
pub_c = ops.EC_POINT_SUB(pub_a, pub_b)

# Get generator point from curve
gen_point = ops.CURVE_GET_GENERATOR(ec.SECP256K1())

# Get order of curve
order = ops.CURVE_GET_ORDER(ec.SECP256K1())
```

# Installation:
1. Clone or download the repository
2. Ensure that you have cryptography.io install (`pip install cryptography`)
3. `python setup.py install`

# TODO:
1. Testing!
2. Get setup on pypy.
