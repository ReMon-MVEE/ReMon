#!/usr/bin/env ruby

@musl=`which musl-gcc`
if `getconf LONG_BIT`.chop == "64"
  @comp="comp_amd64.sh"
else
  @comp="comp_i386.sh"
end

if not @musl.start_with?("/usr/bin/musl-gcc")
  print("ERROR: You need musl libc to compile the MVEE LD Loader!\n")
  print("ERROR: use 'sudo apt-get install musl-tools' to install\n")
  exit(-1)
end

if not File.exists?("MVEE_LD_Loader/MVEE_LD_Loader")
  Dir.chdir("MVEE_LD_Loader")
  `./#{@comp}`
end

if not File.exists?("MVEE_LD_Loader")
  print("ERROR: MVEE LD Loader compilation failed!\n")
  exit(-1)
end
