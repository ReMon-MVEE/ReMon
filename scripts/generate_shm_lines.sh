#!/bin/bash
set -o errexit
set -o pipefail
set -o nounset
#set -o xtrace

# Check the number of parameters
if [ "$#" -lt 2 ]; then
  echo "Illegal number of parameters. Expected a path to a binary, and an input non-instrumented.csv. Optionally, the path to llvm-addr2line."
  exit 1
fi

# Decode arguments
BINARY=$1
BINARY_NAME=$(basename $1)
INPUT_LOG=$2

if [ "$#" -eq 3 ]; then
  # Get it from command line
  ADDR2LINE=$3
else
  # Default docker path
  ADDR2LINE=/opt/deps/llvm/build-tree/bin/llvm-addr2line
fi

grep $BINARY_NAME $INPUT_LOG | cut -d ';' -f 4 | sed -e 's/^/0x/' | xargs $ADDR2LINE -e $BINARY --output-style=LLVM | sort | uniq
