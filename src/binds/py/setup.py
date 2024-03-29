#
# Copyright (c) 2023, Rafael Santiago
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.
#
from distutils.core import setup
from distutils.extension import Extension
from Cython.Build import cythonize

setup(
    name = 'macgonuts',
    ext_modules=cythonize([
        Extension("macgonuts", ["macgonuts_pybind.pyx", "macgonuts.c", "../macgonuts_binds.c"],
                  include_dirs=['../..'],
                  library_dirs=['../../../lib','../../libs/accacia/lib'],
                  libraries=['macgonuts', 'macgonutssock','accacia']),
    ]),
)
