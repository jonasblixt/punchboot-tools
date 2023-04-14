#!/usr/bin/env python3

from setuptools import setup
from setuptools import Extension
import re

setup(name='punchboot',
      version="1.0.0",
      description="Punchboot tools python wrapper",
      author="Jonas Blixt",
      author_email="jonpe960@gmail.com",
      license="BSD",
      url="https://github.com/jonasblixt/punchboot-tools",
      ext_modules=[
          Extension(name="punchboot",
                        sources=[
                            "python_wrapper.c",
                            "exceptions.c",
                            "../src/sha256.c",
                            "../src/crc.c",
                            "../src/uuid/parse.c",
                            "../src/uuid/unparse.c",
                            "../src/uuid/compare.c",
                            "../src/uuid/pack.c",
                            "../src/uuid/unpack.c"
                        ],
                    libraries=["punchboot"],
                    include_dirs=["../src"],
                    )
      ],
)
