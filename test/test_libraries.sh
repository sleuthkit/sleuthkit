#!/bin/bash

# Test script to run command line tools against disk images to make sure we can process E01, VHD and VMDK
#
# Currently, tests mmls on image files.  Will need to be refactored as we add more tests.

set -o pipefail
echo "Testing libs"

EXIT_FAILURE=1
EXIT_SKIP=77

MMLS_CMD=tools/vstools/mmls
TEST_IMAGE_DIR=${srcdir}/test/data
TEST_IMAGES=("imageformat_mmls_1.vhd" "imageformat_mmls_1.vmdk" "imageformat_mmls_1.E01")
IMGBASE="${TEST_IMAGE_DIR}/imageformat_mmls_1"

if [ -n "$WINEARCH" ]; then
  MMLS_CMD="wine ${MMLS_CMD}.exe"
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
# mmls returns 1 on successful list, which is kind of weird, but we won't change it.
mmls_out="$($MMLS_CMD -i list 2>&1 >/dev/null)"
err=$?
if [ $err -ne 1 ]; then
  echo "$MMLS_CMD Failed to get image list with error $err"
  $MMLS_CMD -i list
  exit $EXIT_FAILURE
fi

imgFormatList="$( echo $mmls_out | sed '1d' | awk '{print $1}')"
echo imgFormatList=$imgFormatList

# Use local test files instead of downloading from google drive
for name in "${TEST_IMAGES[@]}"; do
  if [ ! -f "${TEST_IMAGE_DIR}/${name}" ]; then
    echo "Missing test image for image filename=$name"
    exit $EXIT_FAILURE
  fi
done

# Verify mmls does not return an error with various formats.
if [[ "${imgFormatList}" =~ "vmdk" ]]; then
  $MMLS_CMD ${IMGBASE}.vmdk >/dev/null
  _check_exit_status $? "vmdk"
else
  echo "Tools not compiled with libvmdk"
fi

if [[ "${imgFormatList}" =~ "vhd" ]]; then
  $MMLS_CMD ${IMGBASE}.vhd >/dev/null
  _check_exit_status $? "vhd"
else
  echo "Tools not compiled with libvhdi"
fi

if [[ "${imgFormatList}" =~ "ewf" ]]; then
  $MMLS_CMD ${IMGBASE}.E01 >/dev/null
  _check_exit_status $? "ewf"
else
  echo "Tools not compiled with libewf"
fi
