#!/usr/bin/env python3

import xml.etree.ElementTree as ET
import sys

def remove_creator(input_file, output_file):
    suppress = False
    with open(input_file,"r") as input:
        with open(output_file, 'w') as output:
            for line in input:
                if "<creator" in line:
                    suppress = True
                    continue
                if "</creator" in line:
                    suppress = False
                    continue
                if not suppress:
                    output.write(line)

if __name__ == "__main__":
    remove_creator(sys.argv[1], "/dev/stdout")
