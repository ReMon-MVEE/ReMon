#!/usr/bin/env ruby

require_relative 'common'

@musl=`which musl-gcc`
@comp="comp_#{@arch}.sh"

if not @musl.start_with?("/usr/bin/musl-gcc")
  print("ERROR: You need musl libc to compile the MVEE LD Loader!\n")
  print("ERROR: use 'sudo apt-get install musl-tools' to install\n")
  exit(-1)
end

if not File.exists?("#{@mveeroot}/MVEE_LD_Loader/MVEE_LD_Loader")
  Dir.chdir("#{@mveeroot}/MVEE_LD_Loader")
  `./#{@comp}`

  if not File.exists?("MVEE_LD_Loader")
    print("ERROR: MVEE LD Loader compilation failed!\n")
    exit(-1)
  end
end
