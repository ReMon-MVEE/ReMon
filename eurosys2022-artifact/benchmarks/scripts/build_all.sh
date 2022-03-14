#!/bin/bash
set -e

__home_dir=$(readlink -f $(dirname ${BASH_SOURCE}))


$__home_dir/nginx_build.sh \
        --base-anon        \
        --default-anon     \
        --wrapped-anon


$__home_dir/mplayer_build.sh     \
        --default                \
        --default-no-fast-memcpy \
        --wrapped-full


$__home_dir/pulseaudio_build.sh \
        --default               \
        --wrapped



$__home_dir/fontconfig_build.sh \
        --default               \
        --wrapped


$__home_dir/apache_build.sh \
        --base              \
        --default           \
        --wrapped