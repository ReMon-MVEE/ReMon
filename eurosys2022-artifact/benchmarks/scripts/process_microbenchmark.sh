#!/bin/bash
set -e

cd "$(readlink -f $(dirname ${BASH_SOURCE})/../results/microbenchmark/)"

process ()
{
    sed -ni "/.*>.*:.*ns/p" $1
    python ../../scripts/process_microbenchmark.py $1
}

echo " > native run"
process "native.out"
echo " > wrapped bursts"
process "default.out"
echo " > non-wrapped bursts"
process "stripped.out"