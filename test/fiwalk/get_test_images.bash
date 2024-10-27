#!/bin/bash -ex
#
# Install python virtual environment and run get_test_images.py
#
MYDIR=$(dirname "$0")
pushd $MYDIR
if [ ! -d venv ]; then
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
else
    source venv/bin/activate
fi
popd
python3 $MYDIR/get_test_images.py
