#!/bin/bash -e

TD=test/tools/tool_differ.sh

$TD 'tools/vstools/mmls$EXEEXT -r test_data/exfat1.E01' test/tools/vstools/mmls_output/2
