#!/usr/bin/env python3

from setuptools import setup
from setuptools import Extension
import re


def get_version() -> str:
    _hdr_data: str

    with open("include/pb-tools/pb-tools.h") as f:
        _hdr_data = f.read()

    def _ver_helper(part: str) -> str:
        _result = re.search(f"^#define PB_TOOLS_VERSION_{part} ([0-9]+)$", _hdr_data, re.MULTILINE)

        if _result is None:
            raise ValueError("Could not decode version info")

        return _result.group(1)

    return ".".join([_ver_helper(x) for x in ["MAJOR", "MINOR", "PATCH"]])


setup(
    name="punchboot",
    version=get_version(),
    description="Punchboot tools python wrapper",
    author="Jonas Blixt",
    author_email="jonpe960@gmail.com",
    license="BSD",
    url="https://github.com/jonasblixt/punchboot-tools",
    packages=["punchboot"],
    package_dir={
        "punchboot": "python/punchboot",
    },
    package_data={
        "punchboot": ["py.typed"],
    },
    ext_modules=[
        Extension(
            name="_punchboot",
            sources=[
                "python/python_wrapper.c",
                "python/exceptions.c",
            ],
            libraries=["punchboot"],
        )
    ],
)
