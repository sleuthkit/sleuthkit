#!/bin/bash

set -o pipefail
echo "Testing libs"

# Test script to run command line tools against disk images
#
# Currently, tests mmls on image files.  Will need to be refactored as we add more tests.

ls "$bindir"
EXIT_FAILURE=1
MMLS_CMD=$bindir/mmls
TESTS=("imageformat_mmls_1.vhd" "imageformat_mmls_1.vmdk" "imageformat_mmls_1.E01")

if [ -n "$WINEARCH" ]; then
  MMLS_CMD+='.exe'
  wine "$MMLS_CMD -i list"
fi

# exits with FAILURE status if the command failed
_check_exit_status() {
  if [ "$1" -eq 0 ]; then
    echo "$2 test passed"
  else
    echo "$2 test failed"
    exit $EXIT_FAILURE
  fi
}

# save list of supported images
imgFormatList="$($MMLS_CMD -i list 2>&1 >/dev/null | sed '1d' | awk '{print $1}')"
# mmls returns 1 on successful list. How neat
err=$?
if [ $err -ne 1 ]; then
  echo "Failed to get image list with error $err"
  $MMLS_CMD -i list
  exit $EXIT_FAILURE
fi

# Use local test files instead of downloading from google drive
for name in "${TESTS[@]}"; do
  if [ ! -f "./data/${name}" ]; then
    echo "Missing test $name"
    exit $EXIT_FAILURE
  fi
done

# Verify mmls does not return an error with various formats.
if [[ "${imgFormatList}" =~ "vmdk" ]]; then
  $MMLS_CMD ./data/imageformat_mmls_1.vmdk >/dev/null
  _check_exit_status $? "vmdk"
else
  echo "Tools not compiled with libvmdk"
fi

if [[ "${imgFormatList}" =~ "vhd" ]]; then
  $MMLS_CMD ./data/imageformat_mmls_1.vhd >/dev/null
  _check_exit_status $? "vhd"
else
  echo "Tools not compiled with libvhdi"
fi

if [[ "${imgFormatList}" =~ "ewf" ]]; then
  $MMLS_CMD ./data/imageformat_mmls_1.E01 >/dev/null
  _check_exit_status $? "ewf"
else
  echo "Tools not compiled with libewf"
fi
