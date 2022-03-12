#!/bin/bash
set -e

cd "$(readlink -f $(dirname ${BASH_SOURCE})/../results/nginx/)"

echo " > nginx native run, 1 worker"
python ../../scripts/process_wrk "nginx-native-1worker"

echo " > nginx non-insturmented shm accesses run, 1 worker"
python ../../scripts/process_wrk "nginx-default-1worker"

echo " > nginx insturmented shm accesses run, 1 worker"
python ../../scripts/process_wrk "nginx-wrapped-1worker"

echo " > nginx native run, 2 workers"
python ../../scripts/process_wrk "nginx-native-2worker"

echo " > nginx non-insturmented shm accesses run, 2 workers"
python ../../scripts/process_wrk "nginx-default-2worker"

echo " > nginx insturmented shm accesses run, 2 workers"
python ../../scripts/process_wrk "nginx-wrapped-2worker"
