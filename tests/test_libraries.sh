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
  fi
done

#exits with FAILURE status if the command failed
checkExitStatus (){
	if [ $1 -eq 0 ];then
                echo "$2 test passed"
        else
                echo "$2 test failed"
                exit $EXIT_FAILURE
        fi 	
}

#command to check on the images
mmls_cmd=../tools/vstools/mmls

#saving the list of supported images to dev variable
imgFormatList=$($mmls_cmd -i list 2>&1 > /dev/null | sed '1d' |awk '{print $1}')

# Verify mmls does not return an error with various formats. 
if [[ "${imgFormatList}" =~ "vmdk" ]]; then
	$mmls_cmd ./data/imageformat_mmls_1.vmdk > /dev/null
	checkExitStatus $? "vmdk"
else
	echo "Tools not compiled with libvmdk"
fi

if [[ "${imgFormatList}" =~ "vhd" ]]; then
	$mmls_cmd ./data/imageformat_mmls_1.vhd > /dev/null
	checkExitStatus $? "vhd"
else
	echo "Tools not compiled with libvhdi"
fi

if [[ "${imgFormatList}" =~ "ewf" ]]; then
	$mmls_cmd ./data/imageformat_mmls_1.E01 > /dev/null
	checkExitStatus $? "ewf"
else
	echo "Tools not compiled with libewf"
fi
