@echo off

REM Launch a Cygwin shell with the needed Visual Studio 2010 environment variables set.
REM Used to run the automated build / release scripts that are written in Perl/Python.

CALL "C:\Program Files (x86)\Microsoft Visual Studio 10.0\VC\vcvarsall.bat"

C:
chdir C:\cygwin\bin
bash --login -i