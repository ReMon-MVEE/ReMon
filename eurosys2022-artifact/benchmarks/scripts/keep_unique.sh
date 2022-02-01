#!/bin/bash

__current_directory=$(pwd)
__out="$__current_directory/$1"
__in=$(cat "$__out")

__seen_array=""
> "$__out"
for __line in $__in
do
  if [[ ! "${__seen_array[@]}" =~ "$__line" ]]
  then
    __seen_array+=("$__line")
    echo "$__line" >> "$__out"
  else
    echo " > removing duplicate $__line"
  fi
done