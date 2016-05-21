#!/usr/bin/env ruby

require 'pty'

if ARGV.size < 1
  print("syntax: #{$PROGRAM_NAME} file\n")
  exit
end

def write_addr(fin, addr)
  fin.printf("#{addr}\n")
end

def read_addr(fout)
  buffer = ""
  newlines = 0
  loop {
    chr = fout.getbyte
    break if not chr
    buffer << chr.chr if newlines == 1 and chr != 10 and chr != 13
    if chr == 13
      newlines += 1
      break if newlines == 2
    end
  }
  out = ""
  a = buffer.split(" ")
  out << a[2] << " in " << a[0] if a[2] and a[0]
  out
end

def dump_lines(arr)
  resolv_out, resolv_in, resolv_pid = PTY.spawn("addr2line -e #{ARGV[0]} -f -p -C")

  instolines = Hash.new
  linestocount = Hash.new

  arr.each{ |ins| 
    write_addr(resolv_in, ins)

    instolines[ins] = read_addr(resolv_out)
    linestocount[instolines[ins]] = 0 if not linestocount[instolines[ins]]
    linestocount[instolines[ins]] += 1
  }

  linestocount.sort.map { |line, count|
    print("=> % 4d occurences of: #{line}\n" % count)
  }
end

print("Looking for ad hoc synchronization in file: #{ARGV[0]}\n")

lock_insns=`objdump --disassemble #{ARGV[0]} | grep "lock " | cut -d':' -f1 | sed 's/ *//' | uniq`
arr=lock_insns.split("\n")
print("=> found #{arr.size} instructions with lock prefixes\n")
dump_lines(arr)

implicit_lock_insns=`objdump --disassemble #{ARGV[0]} | grep "xchg" | grep -v "xchg   %ax,%ax" | grep -v "lock " | cut -d':' -f1 |  sed 's/ *//' | uniq`
arr=implicit_lock_insns.split("\n")
print("=> found #{arr.size} instructions with implicit lock prefixes\n")
dump_lines(arr)

fence_insns=`objdump --disassemble #{ARGV[0]} | grep "fence" | cut -d':' -f1 |  sed 's/ *//' | uniq`
arr=fence_insns.split("\n")
print("=> found #{arr.size} fence instructions\n")
dump_lines(arr)





