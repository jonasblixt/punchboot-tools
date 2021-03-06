.. image:: https://readthedocs.org/projects/punchboot-tools/badge/?version=latest
  :target: https://punchboot-tools.readthedocs.io/en/latest/?badge=latest
  :alt: Documentation Status
.. image:: https://ci.appveyor.com/api/projects/status/2x6idm34r66e0o00/branch/master?svg=true
  :target: https://ci.appveyor.com/project/jonasblixt/punchboot-tools/branch/master
  :alt: Windows build status
.. image:: https://travis-ci.com/jonasblixt/punchboot-tools.svg?branch=master
    :target: https://travis-ci.com/jonasblixt/punchboot-tools
.. image:: https://codecov.io/gh/jonasblixt/punchboot-tools/branch/master/graph/badge.svg
  :target: https://codecov.io/gh/jonasblixt/punchboot-tools

Punchboot is a secure and fast bootloader for embedded systems. It is designed to:
 - Boot as fast as possible
 - Integrate with the SoC's secure boot functionality
 - Authenticate the next piece of software in the boot chain
 - Support A/B system partitions for atomic updates
 - Support automatic rollbacks
 - Minimize software download time in production
 - Be useful for day-to-day development

Punchboot is designed for embedded systems and therefore it has a minimalistic 
apporach. There is no run-time configuration, everything is configured in 
the board files.

Punchboot could be useful if you care about the following:
 - Boot speed
 - Secure boot
 - Downloading software quickly in production

Punchboot tools is the host tools used to interact with the punchboot bootloader.
The punchboot tool is a CLI what works on both linux, windows and in the future macos.

Documentation is available here: https://readthedocs.org/projects/punchboot-tools/badge/?version=latest
