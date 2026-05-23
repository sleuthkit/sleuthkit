This document provides information on building the debian package.

Previously, the debian 'deb' packages were built by a perl script that operated on the git repo.

This version builds a deb from the current directory. This has the advantage of allowing the CI/CD system to test building the deb directly and create it as an artifact of the CI/CD process.

References
==========
We found these guides helpful in assembling this document:

* https://askubuntu.com/questions/1345/what-is-the-simplest-debian-packaging-guide
* https://ubuntuforums.org/showthread.php?t=910717 (2006)
* (https://www.debian.org/doc/manuals/maint-guide/)[Debian New Maintainer's Guide]
* (https://www.debian.org/doc/manuals/debian-faq/pkg-basics.en.html)[Chatper 7. Basics of the Debian package management system]
