#!/bin/bash -e

TD=test/tools/tool_differ.sh

$TD 'tools/vstools/mmls$EXEEXT -h' test/tools/vstools/mmls_output/1
