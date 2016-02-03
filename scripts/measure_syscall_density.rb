#!/usr/bin/env ruby

linenum=0
arr=Array.new
`/usr/bin/time -f '%e' /usr/bin/strace -f -c #{ARGV.join(" ")} 2>&1`.each_line { |l|
  arr << l

  if l.match(/^[[:digit:]]+\.[[:digit:]]+$/) and linenum > 0
    syscalls = arr[-2].split(" ")[2]
    print(">>> BENCHMARK SYSCALL DENSITY: #{syscalls.to_f} syscalls / #{l.to_f} seconds = #{syscalls.to_f / l.to_f} syscalls/sec\n")

    open('/home/stijn/MVEE/phoronix-results.txt', 'a') { |f|
      f << "#{ARGV.join(" ")}\n"
      f << "#{syscalls.to_f} syscalls / #{l.to_f} seconds\n"
      f << "#{syscalls.to_f / l.to_f} syscalls/sec\n"
    }
  end

  linenum +=1
}
