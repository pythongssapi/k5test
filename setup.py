#!/usr/bin/env python
from setuptools import setup

setup(
    name="k5test",
    version="0.10.2",
    author="The Python GSSAPI Team",
    author_email="sross@redhat.com",
    packages=["k5test"],
    description="A library for testing Python applications in "
    "self-contained Kerberos 5 environments",
    long_description=open("README.md").read(),
    license="LICENSE.txt",
    url="https://github.com/pythongssapi/k5test",
    python_requires=">=3.6",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: ISC License (ISCL)",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: Implementation :: CPython",
        "Topic :: Security",
    ],
    keywords=["gssapi", "security"],
    install_requires=[],
    extras_require={"extension_test": ["gssapi"]},
)
