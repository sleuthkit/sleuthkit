# setup.py - Builds and installs the TRE Python language bindings module
#
# Copyright (c) 2009 Ville Laurikari <ville@laurikari.net>
#

from distutils.core import setup, Extension
import sys
import os
import shutil

version = "0.8.0"
data_files = []
include_dirs = ["../lib"]
libraries = ["tre"]

if sys.platform == "win32":
    data_files = ["tre.dll"]
    include_dirs += ["../win32"]
    shutil.copy("../win32/Release/tre.dll", ".")
    libraries = ["../win32/Release/tre"]

setup(name = "tre",
      version = version,
      description = "Python module for TRE",
      author = "Ville Laurikari",
      author_email = "ville@laurikari.net",
      license = "2-clause BSD",
      url = "http://laurikari.net/tre/",
      data_files = data_files,
      ext_modules = [Extension("tre",
                               sources = ["tre-python.c"],
                               define_macros = [("HAVE_CONFIG_H", None)],
                               include_dirs = include_dirs,
                               libraries = libraries
                               ),
                     ],
      )
