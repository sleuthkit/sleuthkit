#!/bin/bash -ex
#
# Install python virtual environment and run get_test_images.py
#
pushd test/fiwalk
if [ ! -d venv ]; then
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
else
    source venv/bin/activate
fi
popd
python3 test/fiwalk/get_test_images.py
