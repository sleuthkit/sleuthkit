#!/bin/bash -e

TD=test/tools/tool_differ.sh

$TD 'tools/vstools/mmls$EXEEXT -r $DATA_DIR/from_brian/exfat1.E01' test/tools/vstools/mmls_output/2
$TD 'tools/vstools/mmls$EXEEXT -c $DATA_DIR/from_brian/exfat1.E01' test/tools/vstools/mmls_output/3
