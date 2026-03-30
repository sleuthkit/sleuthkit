#!/bin/bash

# Test script to run command line tools against disk images
#
# Currently, tests mmls on image files.  Will need to be refactored as we add more tests. 

EXIT_FAILURE=1

#create data directory
if [ ! -d "./data" ];then
	mkdir data
	if [ ! -d "./data" ];then
		echo "error creating data directory"
		exit $EXIT_FAILURE
	fi
fi

#Download from images from google drive
ggID=("imageformat_mmls_1.vhd","15vEesL8xTMFSo-uLA5dsx3puVaKcGEyw" "imageformat_mmls_1.vmdk","1uLC0FjUWdl3uLCi1QaZ8O72q281jtzIu" "imageformat_mmls_1.E01","1YBCh3yP4Ny7eads4TC-dL3ycaNNrlzWo")    
for i in ${ggID[@]};do
	name=${i%,*}
  if [ ! -f "./data/${name}" ]; then
    id=${i#*,}
    COOKIES=$(mktemp)
    CODE=$(wget --save-cookies $COOKIES --keep-session-cookies --no-check-certificate "https://docs.google.com/uc?export=download&id=${id}" -O- | sed -rn 's/.*confirm=([0-9A-Za-z_]+).*/Code: \1\n/p')
    CODE=$(echo $CODE | rev | cut -d: -f1 | rev | xargs)
    wget --load-cookies $COOKIES "https://docs.google.com/uc?export=download&confirm=${CODE}&id=${id}" -O ./data/${name}
    rm -f $COOKIES
    if [ ! -f "./data/${name}" ]; then
      echo "Error downloading data (${name})"
      exit $EXIT_FAILURE
    fi 
  fi
done

# runTest <name> <command> [args...]
#   Runs <command> and captures both stdout and stderr.
#   On success, prints "<name> test passed".
#   On failure, prints "<name> test failed" followed by the captured output
#   (so the actual error from the tool is visible) and exits with failure.
#   Stdout is suppressed on success to keep the log clean.
runTest() {
	local name=$1   # human-readable label used in pass/fail messages
	shift           # remaining positional args ($@) are the command to run
	local output
	output=$("$@" 2>&1)   # capture stdout+stderr; suppress on success below
	if [ $? -eq 0 ]; then
		echo "$name test passed"
	else
		echo "$name test failed"
		echo "$output"   # show what the tool printed so the failure is diagnosable
		exit $EXIT_FAILURE
	fi
}

#command to check on the images
mmls_cmd=../tools/vstools/mmls

#saving the list of supported images to dev variable
imgFormatList=$($mmls_cmd -i list 2>&1 > /dev/null | sed '1d' |awk '{print $1}')

# Verify mmls does not return an error with various formats.
if [[ "${imgFormatList}" =~ "vmdk" ]]; then
	runTest "vmdk" $mmls_cmd ./data/imageformat_mmls_1.vmdk
else
	echo "Tools not compiled with libvmdk"
fi

if [[ "${imgFormatList}" =~ "vhd" ]]; then
	runTest "vhd" $mmls_cmd ./data/imageformat_mmls_1.vhd
else
	echo "Tools not compiled with libvhdi"
fi

if [[ "${imgFormatList}" =~ "ewf" ]]; then
	runTest "ewf" $mmls_cmd ./data/imageformat_mmls_1.E01
else
	echo "Tools not compiled with libewf"
fi
