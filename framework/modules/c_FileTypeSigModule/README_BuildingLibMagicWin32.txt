Building libmagic (and libgnurx, I guess):

  First, you need a copy of mingw and msys installed (for convenience, in the
top-level directory (C:)).  Then, you need to go into the mingw-libgnurx-2.5.1
directory in third-party-tools.  From there, run this in an msys shell (yes, it
does matter):

  ./configure --prefix=/mingw && make && make install

  Now you have a copy of libgnurx.  The configure script should be able to tell
that it has to cross-compile, so now you should have a copy of libgnurx-0.dll
installed in the right place (which is under /mingw, because the mingw linker is
funny and doesn't look other places).  Go back to this directory (file-5.08) and
run

  ./configure && make

  There should now be a copy of libmagic-1.dll sitting in src/.libs.   Copy it
into this directory.

Creating libmagic-1.lib:

  Linking against libmagic using Microsoft development tools requires the creation
  of an "import library" (aka a .lib file). You can create the .lib file as follows:
  
  1. Generate a .def file (export definitions) for the dll by running the following 
     commands in your MSYS shell:
  
     a. mingw-get install mingw32-gendef
  
     b. gendef libmagic-1.dll
     
     This will result in a file named libmagic-1.def
     
  2. Generate the .lib file by running the following command in a Microsoft Visual
     Studio shell:
     
     a. lib.exe /machine:i386 /def:libmagic-1.def /out:libmagic-1.lib
     
   That's it. You can now link against libmagic in Visual Studio project files by
   including libmagic-1.lib (and the path in which it lives) as linker settings.