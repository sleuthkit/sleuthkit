@echo off

REM Launch a Cygwin shell with the needed Visual Studio 2019 environment variables set.
REM Used to run the automated build / release scripts that are written in Perl/Python.

CALL "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" x86_amd64

C:
chdir C:\cygwin64\bin
bash --login -i
