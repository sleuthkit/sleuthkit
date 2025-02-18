#!/bin/bash -e

TD=test/tools/tool_differ.sh

$TD 'tools/fstools/fls$EXEEXT' test/tools/fstools/fls_output/1
$TD 'tools/fstools/fls$EXEEXT test/data/image.dd' test/tools/fstools/fls_output/2
