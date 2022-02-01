#!/bin/bash

# This script processes non-instrumented.csv so that -fshm_support can actually use it to wrap shared memory
# instructions.

__non_instrumented=$(cat "$1")
__current_directory=$(pwd)
__non_instrumented_out="$__current_directory/$2"
if [ -n "$2" ]
then
  __non_instrumented_out="$__current_directory/$2"
else
  __non_instrumented_out="$__current_directory/non-instrumented.shm"
fi

__result_array=""
> "$__non_instrumented_out"
for __line in $__non_instrumented
do
  echo "$__current_directory${__line:1}" >> "$__non_instrumented_out"
done
