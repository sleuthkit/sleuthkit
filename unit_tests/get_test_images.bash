#!/bin/bash
#
# Install python virtual environment and run get_test_images.py
#
if [ ! -d venv ]; then
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
else
    source venv/bin/activate
fi
python3 get_test_images.py
