#!/bin/sh
chmod +r $1
echo "Words:" `wc -w $1 | awk '{print $1;}'`
