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

def process_lines(insns)
  noninstrumented_lines = []
  instrumented_lines = []
  all_lines = []
  type3_lines = []
  saw_preop = false
  saw_insn = false

  insns.each_line { |line|
    if line.match(/mvee_atomic_preop/)
      saw_preop = true
      saw_insn = false
    elsif line.match(/mvee_atomic_postop/)
      saw_preop = false

      if not saw_insn
        type3_lines << line.split(":")[0].lstrip
      end
    else
      saw_insn = true
      if not saw_preop
        noninstrumented_lines << line.split(":")[0].lstrip
      else
        instrumented_lines << line.split(":")[0].lstrip
      end
      all_lines << line.split(":")[0].lstrip
    end
  }

  print("Found #{noninstrumented_lines.size} non-instrumented explicit sync ops in file\n")
  if noninstrumented_lines.size > 0
    dump_lines(noninstrumented_lines)
  end

  print("Found #{instrumented_lines.size} instrumented explicit sync ops in file\n")
  if instrumented_lines.size > 0
    dump_lines(instrumented_lines)
  end

  print("Found #{type3_lines.size} instrumented type 3 ops in file\n")
  if type3_lines.size > 0
    dump_lines(type3_lines)
  end
end

print("Looking for ad hoc synchronization in file: #{ARGV[0]}\n")

insns=`objdump --disassemble #{ARGV[0]} | egrep "lock |xchg|mvee\_atomic" | grep -v "xchg *%ax,%ax"`
process_lines(insns)
