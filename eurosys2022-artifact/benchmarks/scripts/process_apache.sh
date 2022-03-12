#!/bin/bash
set -e

cd "$(readlink -f $(dirname ${BASH_SOURCE})/../results/apache/)"

echo " > apache native run, 1 worker"
python ../../scripts/process_wrk.py "apache-native-1worker"

echo " > apache non-insturmented shm accesses run, 1 worker"
python ../../scripts/process_wrk.py "apache-default-1worker"

echo " > apache insturmented shm accesses run, 1 worker"
python ../../scripts/process_wrk.py "apache-wrapped-1worker"

echo " > apache native run, 2 workers"
python ../../scripts/process_wrk.py "apache-native-2worker"

echo " > apache non-insturmented shm accesses run, 2 workers"
python ../../scripts/process_wrk.py "apache-default-2worker"

echo " > apache insturmented shm accesses run, 2 workers"
python ../../scripts/process_wrk.py "apache-wrapped-2worker"
