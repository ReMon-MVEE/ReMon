#!/usr/bin/env ruby

require_relative 'common'

@comp="comp_#{@arch}.sh"
@syncagent="libclang_rt.sync-#{@llvm_arch}.so"

if not File.exists?("#{@mveeroot}/libsync/#{@syncagent}")
  Dir.chdir("#{@mveeroot}/libsync")
  `./#{@comp}`

  if not File.exists?("#{@syncagent}")
    print("ERROR: sync agent compilation failed!\n")
    exit(-1)
  end
end
