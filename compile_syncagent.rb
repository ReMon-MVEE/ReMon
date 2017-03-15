#!/usr/bin/env ruby

if `getconf LONG_BIT`.chop == "64"
  @comp="comp_amd64.sh"
  @syncagent="libclang_rt.sync-x86_64.so"
else
  @comp="comp_i386.sh"
  @syncagent="libclang_rt.sync-i386.so"
end

if not File.exists?("libsync/#{@syncagent}")
  Dir.chdir("libsync")
  `./#{@comp}`

  if not File.exists?("#{@syncagent}")
    print("ERROR: sync agent compilation failed!\n")
    exit(-1)
  end
end
