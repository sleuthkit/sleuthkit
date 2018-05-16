#!/bin/bash

EXIT_FAILURE=1

#https://drive.google.com/open?id=15vEesL8xTMFSo-uLA5dsx3puVaKcGEyw vhd
#https://drive.google.com/open?id=1uLC0FjUWdl3uLCi1QaZ8O72q281jtzIu vmdk
#https://drive.google.com/open?id=1YBCh3yP4Ny7eads4TC-dL3ycaNNrlzWo ewf
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
	id=${i#*,}
	COOKIES=$(mktemp)
	CODE=$(wget --save-cookies $COOKIES --keep-session-cookies --no-check-certificate "https://docs.google.com/uc?export=download&id=${id}" -O- | sed -rn 's/.*confirm=([0-9A-Za-z_]+).*/Code: \1\n/p')
	CODE=$(echo $CODE | rev | cut -d: -f1 | rev | xargs)
	wget --load-cookies $COOKIES "https://docs.google.com/uc?export=download&confirm=${CODE}&id=${id}" -O ./data/${name}
	rm -f $COOKIES
done

#fails the test if the command failed
checkExitStatus (){
	if [ $1 -eq 0 ];then
                echo "$2 test passed"
        else
                echo "$2 test failed"
                exit $EXIT_FAILURE
        fi 	
}

#command to check on the images
cmd=../tools/vstools/mmls


#saving the list of supported images to dev variable
dev=$cmd -i list 2>&1 > /dev/null | sed '1d' |awk '{print $1}'

#testing the sleuthkit using mmls command 

if [[ " ${dev[@]} " =~ " ${vmdk} " ]]; then
	$cmd ./data/imageformat_mmls_1.vmdk > /dev/null
	checkExitStatus $? "vmdk"
else
	echo "libvmdk not found"
	exit $EXIT_FAILURE 
fi

if [[ " ${dev[@]} " =~ " ${vhd} " ]]; then
	$cmd ./data/imageformat_mmls_1.vhd > /dev/null
	checkExitStatus $? "vhd"
else
	echo "libvhdi not found"
	exit $EXIT_FAILURE
fi

if [[ " ${dev[@]}" =~ "${ewf} " ]]; then
	$cmd ./data/imageformat_mmls_1.E01 > /dev/null
	checkExitStatus $? "ewf"
else
	echo "libewf not found"
	exit $EXIT_FAILURE
fi
