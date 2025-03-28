#!/bin/bash -ex
#
# Install python virtual environment in the same directory as this script.
# Then go back to where we were and run get_test_images.py
#
MYDIR=$(dirname "$0")
pushd $MYDIR
if [ ! -d venv ]; then
    python3 -m venv venv
fi
source venv/bin/activate
pip install -r requirements.txt
popd
python3 test/get_images/get_test_images.py
