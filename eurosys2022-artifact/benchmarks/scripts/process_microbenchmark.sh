#!/bin/bash
set -e

cd "$(readlink -f $(dirname ${BASH_SOURCE})/../results/microbenchmark/)"

process ()
{
    sed -ni "/.*>.*:.*ns/p" $1
    python ../../scritps/process_microbenchmark.py $1
}