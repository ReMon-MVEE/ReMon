UNISTD=`./getunistd.rb`
../deps/musl-install/bin/musl-gcc -I./amd64/ -DUNISTD_HDR=\"$UNISTD\" -fuse-ld=bfd -std=c99 -o MVEE_LD_Loader -static MVEE_LD_Loader.c -T linkerscript_amd64.txt
cp MVEE_LD_Loader MVEE_LD_Loader_this_is_a_very_long_process_name_that_must_be_at_least_as_long_as_slash_lib64_slash_ld-linux-x86-64.so.2_times_two
chmod a+x MVEE_LD_Loader_this_is_a_very_long_process_name_that_must_be_at_least_as_long_as_slash_lib64_slash_ld-linux-x86-64.so.2_times_two
