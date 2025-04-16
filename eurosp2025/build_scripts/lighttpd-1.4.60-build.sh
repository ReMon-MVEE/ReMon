#!/bin/bash
set -e

__this_dir=$(readlink -f $(dirname ${BASH_SOURCE}))
__this=$(sed 's#.*/##' <<< "$__this_dir")
cd "$__this_dir"

__pmvee_dir=$(readlink -f ../../PMVEE/)


do_make () 
{
  make clean || true
  make distclean || true
  CFLAGS=$__CFLAGS LDFLAGS=$__LDFLAGS ./configure --prefix="$__prefix"
  make -j"$(nproc)" install

  mkdir -p "../out/$__this/$1/base/log/"
  mkdir -p "../out/$__this/$1/base/www/htdocs"
  mkdir -p "../out/$__this/$1/base/run"
  mkdir -p "../out/$__this/$1/base/conf/"
  cp -r "./doc/config/conf.d" "../out/$__this/$1/base/conf/"
  cp "./doc/config/modules.conf" "../out/$__this/$1/base/conf/"
  cp "../pmvee_config/lighttpd.conf.in" "../out/$__this/$1/base/conf/test.conf"
  cp ../pmvee_config/index.html "../out/$__this/$1/base/www/htdocs/"

  sed -i "s#SET_LOG_ROOT#$__this_dir/../out/$__this/base/log#g"    "../out/$__this/$1/base/conf/test.conf"
  sed -i "s#SET_SERVER_ROOT#$__this_dir/../out/$__this/base/www#g" "../out/$__this/$1/base/conf/test.conf"
  sed -i "s#SET_STATE_DIR#$__this_dir/../out/$__this/base/run#g"   "../out/$__this/$1/base/conf/test.conf"
  sed -i "s#SET_HOME_DIR#$__this_dir/../out/$__this/base#g"         "../out/$__this/$1/base/conf/test.conf"
  sed -i "s#SET_CONF_DIR#$__this_dir/../out/$__this/base/conf#g"   "../out/$__this/$1/base/conf/test.conf"
}

# Common flags: Wrap atomics
__CFLAGS="-O3 -g"

while test $# -gt 0
do
  case $1 in
    --trace)
      CFLAGS="$CFLAGS -pg"
      shift
      ;;
    --base)
      sed -r -i 's/#if 1 \/\/ ifdef PMVEE_CONNECTION_HANDLE_READ_STATE/#ifdef PMVEE_CONNECTION_HANDLE_READ_STATE/g' ./src/connections.c
      sed -r -i 's/#if 1 \/\/ ifdef PMVEE_HTTP_REQUEST_HEADERS_PROCESS/#ifdef PMVEE_HTTP_REQUEST_HEADERS_PROCESS/g' ./src/request.c
      __prefix="$__this_dir/../out/$__this/base"

      export CC="gcc $CFLAGS"
      export CXX="gcc $CFLAGS"

      do_make

      shift
      ;;
    --mappings)
      "$__pmvee_dir"/scripts/generate_mappings.py -s ../pmvee_config/$__this/lighttpd.json -o mappings.pmvee \
          -l "$(readlink -f $__this_dir/../out/$__this/pmvee/leader/sbin/lighttpd)" -f "$(readlink -f $__this_dir/../out/$__this/pmvee/followers/sbin/lighttpd)" \
          --extras ../pmvee_config/lighttpd-1.4.60/extra \
          -sc "$(readlink -f $__this_dir/../out/$__this/pmvee/leader/sbin/lighttpd):$(readlink -f $__this_dir/../out/$__this/pmvee/followers/sbin/lighttpd)" \
          -sm "$(readlink -f $__this_dir/../out/$__this/pmvee/leader/sbin/lighttpd):$(readlink -f $__this_dir/../out/$__this/pmvee/followers/sbin/lighttpd),$__pmvee_dir/allocator/pmvee_allocator_l.so:$__pmvee_dir/allocator/pmvee_allocator_f.so"

      "$__pmvee_dir"/scripts/get_libc_line.sh >> ./mappings.pmvee

      ln -fs $(readlink -f ./mappings.pmvee) ../pmvee_config/mappings.pmvee

      shift
      ;;
    --faster)
      sed -r -i 's/#if 1 \/\/ ifdef PMVEE_CONNECTION_HANDLE_READ_STATE/#ifdef PMVEE_CONNECTION_HANDLE_READ_STATE/g' ./src/connections.c
      sed -r -i 's/#ifdef PMVEE_HTTP_REQUEST_HEADERS_PROCESS/#if 1 \/\/ ifdef PMVEE_HTTP_REQUEST_HEADERS_PROCESS/g' ./src/request.c
      ln -fs $(readlink -f ../pmvee_config/$__this/lighttpd-faster.json) ../pmvee_config/$__this/lighttpd.json
      shift
      ;;
    --default)

      sed -r -i 's/#ifdef PMVEE_CONNECTION_HANDLE_READ_STATE/#if 1 \/\/ ifdef PMVEE_CONNECTION_HANDLE_READ_STATE/g' ./src/connections.c
      sed -r -i 's/#if 1 \/\/ ifdef PMVEE_HTTP_REQUEST_HEADERS_PROCESS/#ifdef PMVEE_HTTP_REQUEST_HEADERS_PROCESS/g' ./src/request.c
      ln -fs $(readlink -f ../pmvee_config/$__this/lighttpd-default.json) ../pmvee_config/$__this/lighttpd.json
      shift
      ;;
    --pmvee)
      mkdir -p ../pmvee_config/$__this/lib/
      "$__pmvee_dir"/scripts/stub_builder_too_lazy_to_do_compiler_stuffz_dl.py -i ../pmvee_config/$__this/lighttpd.json -o ./src/ --no-compile --all-one-file

      __prefix="$__this_dir/../out/$__this/pmvee/leader/"

      __CFLAGS_temp="$__CFLAGS -Wno-unused-function -I$__pmvee_dir"
      __LDFLAGS="-L$__pmvee_dir -lpmvee -Wl,--no-as-needed -ldl"
      __CFLAGS="$__CFLAGS_temp -DPMVEE_FOLLOWER"
      export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$__pmvee_dir"


      export CC="gcc"
      export CXX="gcc"
      do_make
      mkdir -p "$__this_dir/../out/$__this/pmvee/followers/sbin/"
      mv "$__this_dir/../out/$__this/pmvee/leader/sbin/lighttpd" "$__this_dir/../out/$__this/pmvee/followers/sbin/"

      __CFLAGS="$__CFLAGS_temp -DPMVEE_LEADER"
      export CC="gcc"
      export CXX="gcc"
      do_make

      echo "$__this_dir/../out/$__this/pmvee/leader/sbin/lighttpd"

      shift
      ;;
    *)
      echo " > unrecognised option $1"
      exit 1
  esac
done

