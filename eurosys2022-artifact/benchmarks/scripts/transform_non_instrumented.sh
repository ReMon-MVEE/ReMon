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

if [ -n "$3" ]
then
  __llvm_symbolizer="$3/llvm-symbolizer"
else
  __llvm_symbolizer="llvm-symbolizer-6.0"
fi

__result_array=""
for __line in $__non_instrumented
do
  __binary=$(echo "$__line" | cut -d ';' -f 3)
  __offset=$(echo "$__line" | cut -d ';' -f 4)
  __result=($(echo "$__binary 0x$__offset" | $__llvm_symbolizer | sed "2q;d"))
  __file=$(echo $__result | cut -d ":" -f 1)
  echo " > $__result"
  if [[ "$__file" != "${__file##$__current_directory}" ]]
  then
      echo "${__result//$__current_directory/.}" >> "$__non_instrumented_out"
  fi
done
