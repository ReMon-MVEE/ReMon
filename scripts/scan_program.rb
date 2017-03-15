#!/usr/bin/env ruby

if ARGV.size < 1
  print("syntax: #{$PROGRAM_NAME} pid\n")
  exit
end

def print_header(lib)
  print("\n#######################################################################################\n")
  print("Scanning binary: #{lib}\n")
  print("#######################################################################################\n\n")
end

`cat /proc/#{ARGV[0]}/maps | grep " ..x. "`.each_line { |line|
  lib = line.split(" ")[-1]
  next if lib[0] != "/"
  print_header(lib)
  print("#{`./find_noninstrumented_atomics.rb #{lib}`}")
}
