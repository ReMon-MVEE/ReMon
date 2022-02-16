#!/bin/bash

__home_dir="$(readlink -f $(dirname ${BASH_SOURCE}) | sed 's/\//\\\//g')"

__replace="\"variant-B\": { \"exec\": { \"alias\": [ \"$__home_dir\/example1\/bin\/protected=$__home_dir\/example1\/bin\/protected_2\", \"$__home_dir\/example1\/bin\/wrapped=$__home_dir\/example1\/bin\/wrapped_2\", \"$__home_dir\/example2\/bin\/protected=$__home_dir\/example2\/bin\/protected_2\", \"$__home_dir\/example2\/bin\/wrapped=$__home_dir\/example2\/bin\/wrapped_2\" ] } } }"

sed -i "s/\".*variant-B\": {.*/$__replace/g" ../../../../MVEE/bin/Debug/MVEE.ini
sed -i "s/\".*variant-B\": {.*/$__replace/g" ../../../../MVEE/bin/Release/MVEE.ini