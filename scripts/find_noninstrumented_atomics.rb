#!/usr/bin/env ruby

require 'pty'

@llvm = true
@symbolizer = File.dirname(__FILE__) + "/../deps/llvm/build-tree/bin/llvm-symbolizer"

if ARGV.size < 1
  print("syntax: #{$PROGRAM_NAME} file\n")
  exit
end

def write_addr(fin, addr)
  if not @llvm
    fin.printf("#{addr}\n")
  else
    fin.printf("0x#{addr}\n")
  end
end

def read_addr(fout)
  buffer = ""
  lines = 0
  loop {
    chr = fout.gets
    lines += 1
    break if not chr
    break if chr.chomp('') == ""

    buffer << chr
    if not @llvm
      break if lines == 2
    end
  }

  out = ""
  firstline = buffer.split("\n")[1]
  lastline = buffer.split("\n")[-1]
  a = lastline.split(" ")
  out << a[-1] << " in " << a[-3]
  if lastline.include? "inlined"
    b = firstline.split(" ")
    out << " (inlined from" << b[-1] << " in " << b[-3] << ")"
  end
  out
end

def dump_lines(arr)
  if not @llvm
    # binutils addr2line doesn't output an empty line after each request.
    # If we request addr2line info for inlined funcs too, we won't know when the output will stop
    resolv_out, resolv_in, resolv_pid = PTY.spawn("addr2line -e #{ARGV[0]} -f -p -C")
  else
    resolv_out, resolv_in, resolv_pid = PTY.spawn("#{@symbolizer} -inlining -pretty-print -obj=#{ARGV[0]}")
  end
  
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

  @llvm = false if not File.exist? @symbolizer

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

insns=`objdump --disassemble #{ARGV[0]} | egrep "lock |xchg|mvee\_atomic" | grep -v "xchg *%[a-z0-9]*,%[a-z0-9]*$"`
process_lines(insns)
