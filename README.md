# hazmat-math
Hazmat ECC arithmetic for Cryptography.io

Hazmat math implements some basic ECC arithmetic for use with Cryptography.io objects using the OpenSSL backend. Specifically, `_EllipticCurvePrivateKey` and `_EllipticCurvePublicKey`.

Any operations with `EC_POINT` will return an `_EllipticCurvePublicKey` and any operations with `BN` will return an `_EllipticCurvePrivateKey`.

### WARNING:
1. If you don't know what you're doing, you probably shouldn't be using this library.
2. This hasn't had an official security audit. (They are welcome, though.)
3. This hasn't been tested on non-prime order curves (e.g. Curve25519). It is not believed by the author to work on these curves.

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
```

# Installation:
1. Clone or download the repository
2. Ensure that you have cryptography.io install (`pip install cryptography`)
3. `python setup.py install`

# TODO:
1. Testing!
2. Get setup on pypy.
3. Extend arithmetic functionality
4. Expose curve generator point

#

Pull Requests are welcome!

Donations accepted:

3LtQheFpRgKy828GJXAgjL3UN6QFg3AiHL (BTC)

MSC1jLgsWPKgVgqsM2Cs7UBufEgLmPZTE4 (LTC)

0x2D9D6335074Dd581c24EE138f96c1655a107Ef05 (ETH)
