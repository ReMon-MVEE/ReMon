#!/usr/bin/env ruby

@specintresults  = Hash.new
@specfpresults   = Hash.new
@variants        = (2..4)
@specint         = (1..12)
@specfp          = (13..29)
@runs            = 5

def get_bench_name(benchnum)
  _benchname=`grep "REGISTER.*(#{benchnum}," ../../Src/MVEE_demos.cpp`.split('"')[1]
  return _benchname if _benchname
  "dunno"
end

def run_bench(benchnum, variants, native, force_pie)
  arr = Array.new
  `./MVEE #{benchnum} #{variants} #{"-n" if native} #{"-f1" if force_pie} 2>&1`.each_line { |ln|
    arr << ln
    if ln.match(/ERROR/) or ln.match(/Killed/)
      p arr
      return -1.0
    end
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
    @variants.each { |variants|
      columns << "GHUMVEE (#{variants} Variants);"
    }
    print_spreadsheet(file, columns + "\n")

    results.each { |benchname, benchtable|
      print_spreadsheet(file, benchname + ";")
      benchtable.each_value { |arr|
        min = 10000.0
        max = 0.0
        avg = 0.0
        arr.each { |val|
          avg += val
          min = val if val <= min
          max = val if val >= min
        }
        avg -= min 
        avg -= max
        avg /= (arr.size - 2)
        print_spreadsheet(file, "#{avg.to_s.gsub(".", ",")};")
      }
      print_spreadsheet(file, "\n")
    }

    print("\n")
  }
end

def run_suite(suite, results)
  # print("Native - non-PIE:\n")
  
  # suite.each { |num|
  #   benchname = get_bench_name(num)
  #   print("    #{benchname}\n")
  #   (1..@runs).each { |tmp|
  #     res = run_bench(num, 1, true, false)
  #     results[benchname] = Hash.new if not results[benchname]
  #     results[benchname][0] = Array.new if not results[benchname][0]
  #     results[benchname][0] << res
  #     print("        #{res}\n")
  #   }
  # }

  # print("Native - PIE:\n")
  
  # suite.each { |num|
  #   benchname = get_bench_name(num)
  #   print("    #{benchname}\n")
  #   (1..@runs).each { |tmp|
  #     res = run_bench(num, 1, true, true)
  #     results[benchname] = Hash.new if not results[benchname]
  #     results[benchname][1] = Array.new if not results[benchname][1]
  #     results[benchname][1] << res
  #     print("        #{res}\n")
  #   }
  # }

  @variants.each { |variants|
    print("#{variants} variants:\n")
    suite.each { |num|
      benchname = get_bench_name(num)
      print("    #{benchname}\n")
      (1..@runs).each { |tmp|
        res = run_bench(num, variants, false, false)
        results[benchname] = Hash.new if not results[benchname]
        results[benchname][variants] = Array.new if not results[benchname][variants]
        results[benchname][variants] << res
        print("        #{res}\n")
      }
    }
  }  
end

`sudo sysctl -w kernel.randomize_va_space=1`
print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n")
print("@" + "SPECINT 2006".center(78) + "@\n")
print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\n")
run_suite(@specint, @specintresults)

print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n")
print("@" + "SPECFP 2006".center(78) + "@\n")
print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\n")

run_suite(@specfp, @specfpresults)

dump_spreadsheet("specint.csv", @specintresults)
dump_spreadsheet("specfp.csv", @specfpresults)
