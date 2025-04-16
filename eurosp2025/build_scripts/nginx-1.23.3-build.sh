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
  ./auto/configure --prefix="$__prefix" --with-http_ssl_module $1 \
    --with-cc-opt="-O3 -I"$__pmvee_dir"/  $__CFLAGS" \
    --with-ld-opt="-L"$__pmvee_dir"/ -lpmvee $__LFLAGS"
  make -j"$(nproc)" install
  ln -fs "$__this_dir/cert/*" "$__prefix/conf/"
  ln -fs "$__this_dir/conf/nginx.conf" "$__prefix/conf/"

  cp $__this_dir/../pmvee_config/index.html $__prefix/html/
}


ngx_none ()
{
  sed -r -i 's/#if 1 \/\/ ifdef __PMVEE_REAL_NGX_HTTP_PROCESS_REQUEST_LINE/#ifdef __PMVEE_REAL_NGX_HTTP_PROCESS_REQUEST_LINE/g' ./src/http/ngx_http_request.c
  sed -r -i 's/#if 1 \/\/ ifdef __PMVEE_REAL_NGX_HTTP_PROCESS_REQUEST_LINE/#ifdef __PMVEE_REAL_NGX_HTTP_PROCESS_REQUEST_LINE/g' ./src/http/modules/ngx_http_log_module.c
  sed -r -i 's/#if 1 \/\/ ifdef __PMVEE_REAL_NGX_HTTP_WAIT_REQUEST_HANDLER/#ifdef __PMVEE_REAL_NGX_HTTP_WAIT_REQUEST_HANDLER/g' ./src/http/ngx_http_request.c
  sed -r -i 's/#if 1 \/\/ ifdef __PMVEE_REAL_NGX_HTTP_HANDLER/#ifdef __PMVEE_REAL_NGX_HTTP_HANDLER/g' ./src/http/ngx_http_core_module.c
  sed -r -i 's/#if 1 \/\/ ifdef __PMVEE_REAL_NGX_HTTP_HANDLER/#ifdef __PMVEE_REAL_NGX_HTTP_HANDLER/g' ./src/http/ngx_http.h
  sed -r -i 's/#if 1 \/\/ ifdef __PMVEE_REAL_NGX_HTTP_HANDLER/#ifdef __PMVEE_REAL_NGX_HTTP_HANDLER/g' ./src/http/modules/ngx_http_log_module.c
  sed -r -i 's/#if 1 \/\/ ifdef __PMVEE_REAL_NGX_HTTP_HANDLER/#ifdef __PMVEE_REAL_NGX_HTTP_HANDLER/g' ./src/http/ngx_http_request.c
}


ngx_full ()
{
  sed -r -i 's/#ifdef __PMVEE_REAL_NGX_HTTP_PROCESS_REQUEST_LINE/#if 1 \/\/ ifdef __PMVEE_REAL_NGX_HTTP_PROCESS_REQUEST_LINE/g' ./src/http/ngx_http_request.c
  sed -r -i 's/#ifdef __PMVEE_REAL_NGX_HTTP_PROCESS_REQUEST_LINE/#if 1 \/\/ ifdef __PMVEE_REAL_NGX_HTTP_PROCESS_REQUEST_LINE/g' ./src/http/modules/ngx_http_log_module.c
  sed -r -i 's/#if 1 \/\/ ifdef __PMVEE_REAL_NGX_HTTP_WAIT_REQUEST_HANDLER/#ifdef __PMVEE_REAL_NGX_HTTP_WAIT_REQUEST_HANDLER/g' ./src/http/ngx_http_request.c
  sed -r -i 's/#if 1 \/\/ ifdef __PMVEE_REAL_NGX_HTTP_HANDLER/#ifdef __PMVEE_REAL_NGX_HTTP_HANDLER/g' ./src/http/ngx_http_core_module.c
  sed -r -i 's/#if 1 \/\/ ifdef __PMVEE_REAL_NGX_HTTP_HANDLER/#ifdef __PMVEE_REAL_NGX_HTTP_HANDLER/g' ./src/http/ngx_http.h
  sed -r -i 's/#if 1 \/\/ ifdef __PMVEE_REAL_NGX_HTTP_HANDLER/#ifdef __PMVEE_REAL_NGX_HTTP_HANDLER/g' ./src/http/modules/ngx_http_log_module.c
  sed -r -i 's/#if 1 \/\/ ifdef __PMVEE_REAL_NGX_HTTP_HANDLER/#ifdef __PMVEE_REAL_NGX_HTTP_HANDLER/g' ./src/http/ngx_http_request.c
  ln -fs $(readlink -f "../pmvee_config/$__this/nginx-full.json") ../pmvee_config/$__this/nginx.json
}


ngx_split ()
{
  sed -r -i 's/#ifdef __PMVEE_REAL_NGX_HTTP_PROCESS_REQUEST_LINE/#if 1 \/\/ ifdef __PMVEE_REAL_NGX_HTTP_PROCESS_REQUEST_LINE/g' ./src/http/ngx_http_request.c
  sed -r -i 's/#ifdef __PMVEE_REAL_NGX_HTTP_PROCESS_REQUEST_LINE/#if 1 \/\/ ifdef __PMVEE_REAL_NGX_HTTP_PROCESS_REQUEST_LINE/g' ./src/http/modules/ngx_http_log_module.c
  sed -r -i 's/#if 1 \/\/ ifdef __PMVEE_REAL_NGX_HTTP_WAIT_REQUEST_HANDLER/#ifdef __PMVEE_REAL_NGX_HTTP_WAIT_REQUEST_HANDLER/g' ./src/http/ngx_http_request.c
  sed -r -i 's/#ifdef __PMVEE_REAL_NGX_HTTP_HANDLER/#if 1 \/\/ ifdef __PMVEE_REAL_NGX_HTTP_HANDLER/g' ./src/http/ngx_http_core_module.c
  sed -r -i 's/#ifdef __PMVEE_REAL_NGX_HTTP_HANDLER/#if 1 \/\/ ifdef __PMVEE_REAL_NGX_HTTP_HANDLER/g' ./src/http/ngx_http.h
  sed -r -i 's/#ifdef __PMVEE_REAL_NGX_HTTP_HANDLER/#if 1 \/\/ ifdef __PMVEE_REAL_NGX_HTTP_HANDLER/g' ./src/http/modules/ngx_http_log_module.c
  sed -r -i 's/#ifdef __PMVEE_REAL_NGX_HTTP_HANDLER/#if 1 \/\/ ifdef __PMVEE_REAL_NGX_HTTP_HANDLER/g' ./src/http/ngx_http_request.c
  ln -fs $(readlink -f "../pmvee_config/$__this/nginx-http_handler_exit.json") ../pmvee_config/$__this/nginx.json
}


ngx_handler ()
{
  sed -r -i 's/#if 1 \/\/ ifdef __PMVEE_REAL_NGX_HTTP_PROCESS_REQUEST_LINE/#ifdef __PMVEE_REAL_NGX_HTTP_PROCESS_REQUEST_LINE/g' ./src/http/ngx_http_request.c
  sed -r -i 's/#if 1 \/\/ ifdef __PMVEE_REAL_NGX_HTTP_PROCESS_REQUEST_LINE/#ifdef __PMVEE_REAL_NGX_HTTP_PROCESS_REQUEST_LINE/g' ./src/http/modules/ngx_http_log_module.c
  sed -r -i 's/#ifdef __PMVEE_REAL_NGX_HTTP_WAIT_REQUEST_HANDLER/#if 1 \/\/ ifdef __PMVEE_REAL_NGX_HTTP_WAIT_REQUEST_HANDLER/g' ./src/http/ngx_http_request.c
  sed -r -i 's/#if 1 \/\/ ifdef __PMVEE_REAL_NGX_HTTP_HANDLER/#ifdef __PMVEE_REAL_NGX_HTTP_HANDLER/g' ./src/http/ngx_http_core_module.c
  sed -r -i 's/#if 1 \/\/ ifdef __PMVEE_REAL_NGX_HTTP_HANDLER/#ifdef __PMVEE_REAL_NGX_HTTP_HANDLER/g' ./src/http/ngx_http.h
  sed -r -i 's/#if 1 \/\/ ifdef __PMVEE_REAL_NGX_HTTP_HANDLER/#ifdef __PMVEE_REAL_NGX_HTTP_HANDLER/g' ./src/http/modules/ngx_http_log_module.c
  sed -r -i 's/#if 1 \/\/ ifdef __PMVEE_REAL_NGX_HTTP_HANDLER/#ifdef __PMVEE_REAL_NGX_HTTP_HANDLER/g' ./src/http/ngx_http_request.c
  ln -fs $(readlink -f "../pmvee_config/$__this/nginx-ngx_http_wait_request_handler.json") ../pmvee_config/$__this/nginx.json
}

# Common flags: Wrap atomics
__CFLAGS=""
__CFLAGS_temp=""

__old=$(readlink -f "../pmvee_config/$__this/nginx.json" || echo "/dev/null")

while test $# -gt 0
do
  case $1 in
    --trace)
      __CFLAGS="$__CFLAGS -pg -g"
      shift
      ;;
    --disable-state)
      __CFLAGS_temp="$__CFLAGS_temp -DPMVEE_DISABLE_STATE_MIGRATION"
      shift
      ;;
    --ngx-none)
      ngx_none
      shift
      ;;
    --ngx-full)
      ngx_full
      shift
      ;;
    --ngx-split)
      ngx_split
      shift
      ;;
    --ngx-handler)
      ngx_handler
      shift
      ;;
    --base)
      __prefix="$__this_dir/../out/$__this/base"

      # export CC="gcc $__CFLAGS"
      # export CXX="gcc $__CFLAGS"
      __CFLAGS=""
      __LFLAGS=""

      ngx_none
      do_make
      ngx_split
      shift
      ;;
    --pmvee-dl)
      mkdir -p ../pmvee_config/nginx-1.23.3/lib/
      rm -rf ../pmvee_config/nginx-1.23.3/lib/*
      "$__pmvee_dir"/scripts/stub_builder_too_lazy_to_do_compiler_stuffz_dl.py -i ../pmvee_config/nginx-1.23.3/nginx.json -o ../pmvee_config/nginx-1.23.3/lib/

      __prefix="$__this_dir/../out/$__this/pmvee/dl/"

      __CFLAGS="$__CFLAGS_temp -Wno-unused-function -I../pmvee_config/nginx-1.23.3/lib/"
      export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$__pmvee_dir"

      export CC="gcc"
      export CXX="gcc"
      do_make

      "$__pmvee_dir"/scripts/generate_mappings.py -s ../pmvee_config/nginx-1.23.3/nginx.json -o mappings.pmvee \
        -l "$(readlink -f ../pmvee_config/nginx-1.23.3/lib/nginx_l.so)"                                        \
        -f "$(readlink -f ../pmvee_config/nginx-1.23.3/lib/nginx_f.so)"                                        \
        --extras "../pmvee_config/nginx-1.23.3/extra_leader_single"                                            \
        -sm "$__pmvee_dir/allocator/pmvee_allocator_l.so:$__pmvee_dir/allocator/pmvee_allocator_f.so"

      "$__pmvee_dir"/scripts/get_libc_line.sh >> ./mappings.pmvee

      ln -fs $(readlink -f ./mappings.pmvee) ../pmvee_config/mappings.pmvee
      ln -fs $(readlink -f ./migrations.pmvee) ../pmvee_config/migrations.pmvee
      "$__pmvee_dir"/scripts/process_migration.py ../pmvee_config/nginx-1.23.3/migrations.csv ./migrations.pmvee

      shift
      ;;
    --pmvee-stubs)

      mkdir -p ../pmvee_config/nginx-1.23.3/lib/
      rm -rf ../pmvee_config/nginx-1.23.3/lib/*
      "$__pmvee_dir"/scripts/stub_builder_too_lazy_to_do_compiler_stuffz_dl.py -i ../pmvee_config/nginx-1.23.3/nginx.json -o ../pmvee_config/nginx-1.23.3/lib/

      shift
      ;;
    --mappings-single-scanning)
      "$__pmvee_dir"/scripts/generate_mappings.py -s ../pmvee_config/nginx-1.23.3/nginx.json -o mappings.pmvee \
        -l "$(readlink -f ../pmvee_config/nginx-1.23.3/lib/nginx_l.so)"                                        \
        -f "$(readlink -f ../pmvee_config/nginx-1.23.3/lib/nginx_f.so)"                                        \
        --extras "../pmvee_config/nginx-1.23.3/extra_leader_single"                                            \
        -sm "$__pmvee_dir/allocator/pmvee_allocator_l.so:$__pmvee_dir/allocator/pmvee_allocator_f.so"

      "$__pmvee_dir"/scripts/get_libc_line.sh >> ./mappings.pmvee

      ln -fs $(readlink -f ./mappings.pmvee) ../pmvee_config/mappings.pmvee
      ln -fs $(readlink -f ./migrations.pmvee) ../pmvee_config/migrations.pmvee
      "$__pmvee_dir"/scripts/process_migration.py ../pmvee_config/nginx-1.23.3/migrations.csv ./migrations.pmvee

      ln -fs "$__old" "../pmvee_config/$__this/nginx.json"

      shift
      ;;
    --pmvee-single-scanning)
      ngx_split
      ln -fs $(readlink -f "../pmvee_config/$__this/nginx-http_handler_exit.json") ../pmvee_config/$__this/nginx.json
      mkdir -p ../pmvee_config/nginx-1.23.3/lib/
      rm -rf ../pmvee_config/nginx-1.23.3/lib/*
      "$__pmvee_dir"/scripts/stub_builder_too_lazy_to_do_compiler_stuffz_dl.py -i ../pmvee_config/nginx-1.23.3/nginx.json -o ../pmvee_config/nginx-1.23.3/lib/

      __prefix="$__this_dir/../out/$__this/pmvee/single/"

      __CFLAGS="$__CFLAGS_temp -Wno-unused-function -I../pmvee_config/nginx-1.23.3/lib/ -I"$__pmvee_dir"/ -DPMVEE -DPMVEE_DISABLE_STATE_MIGRATION"
      __LFLAGS="-L../pmvee_config/nginx-1.23.3/lib/ -l:nginx_l.so"
      export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$__pmvee_dir"

      export CC="gcc"
      export CXX="gcc"
      do_make

      # cp ./html/* "$__prefix/html/"

      shift
      ;;
    --mappings-single)
      "$__pmvee_dir"/scripts/generate_mappings.py -s ../pmvee_config/nginx-1.23.3/nginx.json -o mappings.pmvee \
        -l "$(readlink -f ../pmvee_config/nginx-1.23.3/lib/nginx_l.so)"                                        \
        -f "$(readlink -f ../pmvee_config/nginx-1.23.3/lib/nginx_f.so)"                                        \
        --extras "../pmvee_config/nginx-1.23.3/extra_leader_single"                                            \
        -sm "$__pmvee_dir/allocator/pmvee_allocator_l.so:$__pmvee_dir/allocator/pmvee_allocator_f.so"

      "$__pmvee_dir"/scripts/get_libc_line.sh >> ./mappings.pmvee

      ln -fs $(readlink -f ./mappings.pmvee) ../pmvee_config/mappings.pmvee
      ln -fs $(readlink -f ./migrations.pmvee) ../pmvee_config/migrations.pmvee
      "$__pmvee_dir"/scripts/process_migration.py ../pmvee_config/nginx-1.23.3/migrations.csv ./migrations.pmvee

      ln -fs "$__old" "../pmvee_config/$__this/nginx.json"

      shift
      ;;
    --pmvee-single)
      ngx_split
      ln -fs $(readlink -f "../pmvee_config/$__this/nginx-http_handler_exit-single.json") ../pmvee_config/$__this/nginx.json
      mkdir -p ../pmvee_config/nginx-1.23.3/lib/
      rm -rf ../pmvee_config/nginx-1.23.3/lib/*
      "$__pmvee_dir"/scripts/stub_builder_too_lazy_to_do_compiler_stuffz_dl.py -i ../pmvee_config/nginx-1.23.3/nginx.json -o ../pmvee_config/nginx-1.23.3/lib/

      __prefix="$__this_dir/../out/$__this/pmvee/single/"

      __CFLAGS="$__CFLAGS_temp -Wno-unused-function -I../pmvee_config/nginx-1.23.3/lib/ -I"$__pmvee_dir"/ -DPMVEE -DPMVEE_DISABLE_STATE_MIGRATION"
      __LFLAGS="-L../pmvee_config/nginx-1.23.3/lib/ -l:nginx_l.so"
      export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$__pmvee_dir"

      export CC="gcc"
      export CXX="gcc"
      do_make

      # cp ./html/* "$__prefix/html/"

      shift
      ;;
    --pmvee-extra)
      ngx_split
      ln -fs $(readlink -f "../pmvee_config/$__this/nginx-http_handler_exit-single-extra.json") ../pmvee_config/$__this/nginx.json
      mkdir -p ../pmvee_config/nginx-1.23.3/lib/
      rm -rf ../pmvee_config/nginx-1.23.3/lib/*
      "$__pmvee_dir"/scripts/stub_builder_too_lazy_to_do_compiler_stuffz_dl.py -i ../pmvee_config/nginx-1.23.3/nginx.json -o ../pmvee_config/nginx-1.23.3/lib/

      __prefix="$__this_dir/../out/$__this/pmvee/single/"

      __CFLAGS="$__CFLAGS_temp -Wno-unused-function -I../pmvee_config/nginx-1.23.3/lib/ -I"$__pmvee_dir"/ -DPMVEE -DPMVEE_DISABLE_STATE_MIGRATION"
      __LFLAGS="-L../pmvee_config/nginx-1.23.3/lib/ -l:nginx_l.so"
      export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$__pmvee_dir"

      export CC="gcc"
      export CXX="gcc"
      do_make

      # cp ./html/* "$__prefix/html/"

      shift
      ;;
    --mappings)
      "$__pmvee_dir"/scripts/generate_mappings.py -s ../pmvee_config/nginx-1.23.3/nginx.json -o mappings.pmvee                                        \
        -l "$(readlink -f ../pmvee_config/nginx-1.23.3/lib/nginx_l.so)"                                                                              \
        -f "$(readlink -f ../pmvee_config/nginx-1.23.3/lib/nginx_f.so)"                                                                              \
        --extras "../pmvee_config/nginx-1.23.3/extra_leader"                                                                                         \
        -sc "$(readlink -f $__this_dir/../out/$__this/pmvee/leader/sbin/nginx):$(readlink -f $__this_dir/../out/$__this/pmvee/followers/sbin/nginx)" \
        -sm "$(readlink -f $__this_dir/../out/$__this/pmvee/leader/sbin/nginx):$(readlink -f $__this_dir/../out/$__this/pmvee/followers/sbin/nginx),$__pmvee_dir/allocator/pmvee_allocator_l.so:$__pmvee_dir/allocator/pmvee_allocator_f.so"

      "$__pmvee_dir"/scripts/get_libc_line.sh >> ./mappings.pmvee

      ln -fs $(readlink -f ./mappings.pmvee) ../pmvee_config/mappings.pmvee

      shift
      ;;
    --pmvee)
      __prefix="$__this_dir/../out/$__this/pmvee/leader/"

      __LFLAGS="-L../pmvee_config/nginx-1.23.3/lib/ -l:nginx_l.so"
      __CFLAGS="$__CFLAGS_temp -Wno-unused-function -I../pmvee_config/nginx-1.23.3/lib/ -DPMVEE -DPMVEE_FOLLOWER"
      export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$__pmvee_dir"

      export CC="gcc"
      export CXX="gcc"
      do_make
      mkdir -p "$__this_dir/../out/$__this/pmvee/followers/sbin/"
      mv "$__this_dir/../out/$__this/pmvee/leader/sbin/nginx" "$__this_dir/../out/$__this/pmvee/followers/sbin/"

      __CFLAGS="$__CFLAGS_temp -Wno-unused-function -I../pmvee_config/nginx-1.23.3/lib/ -DPMVEE -DPMVEE_LEADER ../pmvee_config/nginx-1.23.3/lib/nginx_l.so"
      export CC="gcc"
      export CXX="gcc"
      do_make

      # cp ./html/* "$__prefix/html/"

      shift
      ;;
    --pmvee-debug-follower)
      __prefix="$__this_dir/../out/$__this/pmvee/followers/"

      __LFLAGS="-L../pmvee_config/nginx-1.23.3/lib/ -l:nginx_l.so"
      __CFLAGS="$__CFLAGS_temp -Wno-unused-function -I../pmvee_config/nginx-1.23.3/lib/ -DPMVEE -DPMVEE_LEADER ../pmvee_config/nginx-1.23.3/lib/nginx_l.so"
      export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$__pmvee_dir"


      export CC="gcc"
      export CXX="gcc"
      do_make
      mkdir -p "$__this_dir/../out/$__this/pmvee/leader/sbin/"
      mv "$__this_dir/../out/$__this/pmvee/followers/sbin/nginx" "$__this_dir/../out/$__this/pmvee/leader/sbin/"

      __CFLAGS="$__CFLAGS_temp -Wno-unused-function -I../pmvee_config/nginx-1.23.3/lib/ -DPMVEE -DPMVEE_FOLLOWER"
      export CC="gcc"
      export CXX="gcc"
      do_make

      echo "$__this_dir/../out/$__this/pmvee/leader/sbin/nginx"
      "$__pmvee_dir"/scripts/generate_mappings.py -s ../pmvee_config/nginx-1.23.3/nginx.json -l "$(readlink -f $__this_dir/../out/$__this/pmvee/leader/sbin/nginx)" -f "$(readlink -f $__this_dir/../out/$__this/pmvee/followers/sbin/nginx)" -o mappings.pmvee

      # cp ./html/* "$__prefix/html/"

      shift
      ;;
    # --with-http_mp4_module
    --mp4)
      __prefix="$__this_dir/../out/$__this/mp4"

      export CC="gcc $CFLAGS"
      export CXX="gcc $CFLAGS"

      do_make "--with-http_mp4_module"

      # cp ./html/* "$__prefix/html/"

      shift
      ;;
    *)
      echo " > unrecognised option $1"
      exit 1
  esac
done

if [[ ! -e ../../patched_binaries/gnomelibs/amd64/nginx_l.so ]]
then
  ln -fs $(readlink -f ../pmvee_config/nginx-1.23.3/lib/nginx_l.so) ../../patched_binaries/gnomelibs/amd64/
fi
