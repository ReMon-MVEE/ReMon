#!/usr/bin/env ruby

@results = Hash.new
@inputset  = "native"
#@workers   = (1..8)
@workers   = [4]
#@replicae  = (2..4)
@replicae  = [2]
@splash    = (158..171)
@runs      = 5

def get_bench_name(benchnum)
  benchname=`grep "case #{benchnum}:" -A8 ../../Src/MVEE_demos.cpp | grep splash\_bench | head -n1`.split("\"")[1]
end

def add_result(benchname, replicae, threads, results, seconds)
  results[threads] = Hash.new if not results[threads]
  results[threads][benchname] = Hash.new if not results[threads][benchname]
  results[threads][benchname][replicae] = Array.new if not results[threads][benchname][replicae]
  results[threads][benchname][replicae] << seconds
end

def run_bench(benchnum, replicae, threads, input, results, native)
  benchname=get_bench_name(benchnum)

  # if native
  #   add_result(benchname, 0, threads, results, 0.0)
  #   return
  # end

  `./MVEE #{benchnum} #{replicae} #{threads} #{input} #{"-n" if native} 2>&1`.each_line { |ln|
    if ln.match(/real\t/)
      time = ln.split("\t")[1].chop 
      seconds = Float(time.split("m")[0].to_i * 60) + Float(time.split("m")[1].chop)

      replicae = 0 if native
      add_result(benchname, replicae, threads, results, seconds)

      print("        #{seconds.to_s.gsub(".", ",")}\n")
    end
  }
end

def print_spreadsheet(file, str)
  file.write(str)
  print(str)
end

def dump_spreadsheet(results, threads)
  return if not results[threads]

  print("Spreadsheet for #{threads} worker threads:\n\n")

  File.open("splash2x_#{threads}_workers.csv", "w") { |file|
    columns="Benchmark;Native;"
    @replicae.each { |replicae|
      columns << "GHUMVEE (#{replicae} Replicae);"
    }
    print_spreadsheet(file, columns + "\n")

    results[threads].each { |benchname, benchtable|
      print_spreadsheet(file, benchname + ";")
      benchtable.each_value { |arr|
        avg = 0.0
        arr.each { |val|
          avg += val
        }
        avg /= arr.size
        print_spreadsheet(file, "#{avg.to_s.gsub(".", ",")};")
      }
      print_spreadsheet(file, "\n")
    }

    print("\n")
  }
end

@workers.each { |threads|
  print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n")
  print("@" + "SPLASH2x - #{threads} WORKER THREADS".center(78) + "@\n")
  print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\n")

  print("Native:\n")

  @splash.each { |num| 
    print("    running benchmark: #{get_bench_name(num)}\n")
    (1..@runs).each { run_bench(num, 1, threads, @inputset, @results, true) }
  }

  print("\n")

  @replicae.each { |replicae|
    print("#{replicae} replicae:\n")
    @splash.each { |num| 
      print("    running benchmark: #{get_bench_name(num)}\n")
      (1..@runs).each { run_bench(num, replicae, threads, @inputset, @results, false) }
    }

    print("\n")
  }

  print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n")
}

@workers.each { |threads|
  dump_spreadsheet(@results, threads)
}
