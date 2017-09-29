#!/usr/bin/env ruby

@mveeroot = File.dirname(__FILE__) + "/.."

# Get ABI target
`gcc -v 2>&1`.each_line { |line|
  @target = line.sub("Target: ","").chop if line.match(/^Target: /)
}

# Get word width
@bits = `getconf LONG_BIT`.chop

# find out which file has the syscall numbers
if File.exist? "/usr/include/asm/unistd_#{@bits}.h"
  @unistd="/usr/include/asm/unistd_#{@bits}.h"
elsif File.exist? "/usr/include/asm/unistd.h"
  @unistd="/usr/include/asm/unistd.h"
elsif File.exist? "/usr/include/#{@target}/asm/unistd_#{@bits}.h"
  @unistd="/usr/include/#{@target}/asm/unistd_#{@bits}.h"
else
  @unistd="/usr/include/arm-linux-gnueabihf/asm/unistd.h"
end

# Get GHUMVEE arch
if @target.match(/^arm/)
  @arch="arm"
  @llvm_arch="arm"
elsif @bits == "32"
  @arch="i386"
  @llvm_arch="i386"
else
  @arch="amd64"
  @llvm_arch="x86_64"
end
