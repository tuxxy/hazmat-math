from distutils.core import setup

INSTALL_REQUIRES = ['cryptography']

setup(
    name='hazmat_math',
    version='0.1',
    description='Elliptic curve arithmetic for cryptography.io objects',
    install_requires=INSTALL_REQUIRES,
    packages=['hazmat_math']
)
