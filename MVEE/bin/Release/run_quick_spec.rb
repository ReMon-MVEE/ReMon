#!/usr/bin/env ruby

@specintresults  = Hash.new
@specfpresults   = Hash.new
@replicae        = (2..4)
@specint         = [60, 62, 63, 66, 67, 69, 71]
@specfp          = [118, 119, 120, 121, 123, 124, 126, 127, 130, 131, 132, 133]
@runs            = 3

def install_orig_libc()
  print("Installing original eglibc 2.19\n")
  orig = Dir.pwd
  Dir.chdir(File.expand_path("~/eglibc-builds/eglibc-orig/"))
  `ls -1 | egrep "libc6\_|dbg|libc\-bin" | xargs sudo dpkg -i`
  Dir.chdir(orig)
end

def install_partialorder_libc()
  print("Installing GHUMVEE partial order eglibc 2.19\n")
  orig = Dir.pwd
  Dir.chdir(File.expand_path("~/eglibc-builds/eglibc-mvee-partialorder-nodebugging"))
  `ls -1 | egrep "libc6\_|dbg|libc\-bin" | xargs sudo dpkg -i`
  Dir.chdir(orig)
end

def get_bench_name(benchnum)
  _benchname=`grep "case #{benchnum}:" -A8 ../../Src/MVEE_demos.cpp | grep execl | head -n1`.split(",")[2].match(/[[:digit:]]{3}\.[[:alnum:]]*/)
  return _benchname[0] if _benchname
  "dunno"
end

def run_bench(benchnum, replicae, native)
  `./MVEE #{benchnum} #{replicae} #{"-n" if native} 2>&1`.each_line { |ln|
    return -1.0 if ln.match(/ERROR/)
    return -1.0 if ln.match(/Killed/)
    return ln.chop.to_f if ((ln =~ /[[:digit:]]+\.[[:digit:]]+/) == 0)
  }
end

def print_spreadsheet(file, str)
  file.write(str)
  print(str)
end

def dump_spreadsheet(filename, results)
  print("dumping results to: #{filename}\n")

  File.open(filename, "w") { |file|
    columns="Benchmark;Native (non-PIE);Native (PIE);"
    @replicae.each { |replicae|
      columns << "GHUMVEE (#{replicae} Replicae);"
    }
    print_spreadsheet(file, columns + "\n")

    results.each { |benchname, benchtable|
      print_spreadsheet(file, benchname + ";")
      benchtable.each_value { |arr|
        avg = 0.0
        first = 0.0
        arr.each { |val|
          if first == 0.0
            first = val
          else
            avg += val
          end
        }
        avg /= (arr.size - 1)
        print_spreadsheet(file, "#{avg.to_s.gsub(".", ",")};")
      }
      print_spreadsheet(file, "\n")
    }

    print("\n")
  }
end

def run_suite(suite, results)
  @replicae.each { |replicae|
    print("#{replicae} replicae:\n")
    suite.each { |num|
      benchname = get_bench_name(num)
      print("    #{benchname}\n")
      (1..@runs).each { |tmp|
        res = run_bench(num, replicae, false)
        results[benchname] = Hash.new if not results[benchname]
        results[benchname][replicae] = Array.new if not results[benchname][replicae]
        results[benchname][replicae] << res
        print("        #{res}\n")
        p results
      }
    }
  }  
end

`sudo sysctl -w kernel.yama.ptrace_scope=0`
`sudo sysctl -w kernel.randomize_va_space=1`
print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n")
print("@" + "SPECINT 2006".center(78) + "@\n")
print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\n")
run_suite(@specint, @specintresults)

# print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n")
# print("@" + "SPECFP 2006".center(78) + "@\n")
# print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\n")

# run_suite(@specfp, @specfpresults)

dump_spreadsheet("specint.csv", @specintresults)
#dump_spreadsheet("specfp.csv", @specfpresults)
