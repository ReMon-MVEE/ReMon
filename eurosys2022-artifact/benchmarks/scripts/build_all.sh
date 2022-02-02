#!/bin/bash
set -e

__home_dir=$(readlink -f $(dirname ${BASH_SOURCE}))


$__home_dir/nginx_build.sh \
        --default          \
        --wrapped          \
        --default-anon     \
        --wrapped-anon


$__home_dir/mplayer_build.sh     \
        --default                \
        --wrapped                \
        --default-no-fast-memcpy \
        --wrapped-no-fast-memcpy \
        --default-osd-fixed      \
        --wrapped-osd-fixed      \
        --default-full           \
        --wrapped-full


$__home_dir/pulseaudio_build.sh \
        --default               \
        --wrapped



$__home_dir/fontconfig_build.sh \
        --default               \
        --wrapped


$__home_dir/apache_build.sh \
        --default           \
        --wrapped