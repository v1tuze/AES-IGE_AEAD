"""
AES-IGE-AEAD Python package - CPython C extension
"""
from setuptools import setup, Extension
import os

# Paths relative to this file
base = os.path.dirname(os.path.abspath(__file__))
parent = os.path.dirname(base)
include = os.path.join(parent, "include")
src = os.path.join(parent, "src")

setup(
    name="aes_ige_aead",
    version="1.0.0",
    description="AES-IGE-AEAD: Authenticated encryption (fast CPython C extension)",
    long_description=open(os.path.join(base, "README.md"), encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="",
    license="Public Domain",
    ext_modules=[
        Extension(
            "aes_ige_aead",
            sources=[
                os.path.join(base, "aes_ige_aead.c"),
                os.path.join(src, "sha256.c"),
                os.path.join(src, "aes.c"),
                os.path.join(src, "gf128.c"),
                os.path.join(src, "aes_ige.c"),
                os.path.join(src, "poly_mac.c"),
                os.path.join(src, "aes_ige_aead.c"),
                os.path.join(src, "chacha20.c"),
                os.path.join(src, "poly1305.c"),
                os.path.join(src, "chacha20_poly1305.c"),
            ],
            include_dirs=[include],
            extra_compile_args=["-O2"] if os.name != "nt" else ["/O2"],
        )
    ],
    python_requires=">=3.7",
)
