This directory is used to build and test SleuthKit on Ubuntu, MacOS and Windows. Each directory contains:
     - A Dockerfile (or other virtualization approach) for creating the container or virtual machine
     - A Makefile that contains the commands used to access the container or virtual machine.

Currently this supports:

ubuntu_x86 - Ubuntu x86 running within Docker (or colima on MacOS)
