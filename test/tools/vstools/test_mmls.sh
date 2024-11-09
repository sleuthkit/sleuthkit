#!/bin/bash -e

TD=test/tools/tool_differ.sh

$TD 'tools/vstools/mmls$EXEEXT -h' test/tools/vstools/mmls_output/1
$TD 'tools/vstools/mmls$EXEEXT test/from_brian/gpt_130_partitions.E01' test/tools/vstools/mmls_output/3
$TD 'tools/vstools/mmls$EXEEXT test/from_brian/mbr-disk-image.E01' test/tools/vstools/mmls_output/4
