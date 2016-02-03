#!/usr/bin/env ruby

require 'pty'

@poresults = Hash.new
@toresults = Hash.new
@inputset  = "native"
@workers   = (5..8)
#@replicae  = (2..4)
@replicae  = [2]
#@parsec    = [80, 81, 83, 85, 86, 87, 88, 89, 90, 91, 92]
@parsec    = [92]
@runs      = 15

def get_bench_name(benchnum)
  benchname=`grep "case #{benchnum}:" -A8 ../../Src/MVEE_demos.cpp | grep parsec\_bench | head -n1`.split("\"")[1]
end

def run_bench(benchnum, replicae, threads, input, results, native)
  benchname=get_bench_name(benchnum)
  if native
      results[threads] = Hash.new if not results[threads]
      results[threads][benchname] = Hash.new if not results[threads][benchname]
      results[threads][benchname][0] = Array.new if not results[threads][benchname][0]
      results[threads][benchname][0] << 0.0
    return
  end
    
  PTY.spawn("./MVEE #{benchnum} #{replicae} #{threads} #{input} #{'-n' if native} 2>&1") do |stdout, stdin, pid|
    begin
      stdout.each { |ln|
        if ln.match(/real\t/)
          time = ln.split("\t")[1].chop 
          seconds = Float(time.split("m")[0].to_i * 60) + Float(time.split("m")[1].chop)
          
          replicae = 0 if native
          results[threads] = Hash.new if not results[threads]
          results[threads][benchname] = Hash.new if not results[threads][benchname]
          results[threads][benchname][replicae] = Array.new if not results[threads][benchname][replicae]
          results[threads][benchname][replicae] << seconds
          
          print("        #{seconds.to_s.gsub(".", ",")}\n")
        else 
          if ln.match(/ERROR/)
            print("ERROR: #{ln}\n")
            `killall -9 MVEE MVEE_LD_Loader_`
          end
        end
      }
    rescue Errno::EIO
    end
  end
end

def print_spreadsheet(file, str)
  file.write(str)
  print(str)
end

def dump_spreadsheet(results, prefix, threads)
  return if not results[threads]

  print("Spreadsheet for #{threads} worker threads:\n\n")

  File.open("parsec_#{prefix}_#{threads}_workers.csv", "w") { |file|
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
  print("@" + "PARSEC 2.1 - #{threads} WORKER THREADS".center(78) + "@\n")
  print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\n")

#  install_orig_libc()
  print("Native:\n")

  @parsec.each { |num| 
    print("    running benchmark: #{get_bench_name(num)}\n")
    (1..@runs).each { run_bench(num, 1, threads, @inputset, @poresults, true) }
  }

  print("\n")

#  install_partialorder_libc()
  @replicae.each { |replicae|
    print("#{replicae} replicae:\n")
    @parsec.each { |num| 
      print("    running benchmark: #{get_bench_name(num)}\n")
      (1..@runs).each { run_bench(num, replicae, threads, @inputset, @poresults, false) }
    }

    print("\n")
  }

  # install_totalorder_libc()
  # # copy results of the native benchmark
  # @toresults[threads] = Hash.new
  # @poresults[threads].each { |benchname, benchtable|
  #   @toresults[threads][benchname] = Hash.new
  #   @toresults[threads][benchname][0] = benchtable[0]
  # }
  # @replicae.each { |replicae|
  #   print("#{replicae} replicae:\n")
  #   @parsec.each { |num| 
  #     print("    running benchmark: #{get_bench_name(num)}\n")
  #     (1..@runs).each { run_bench(num, replicae, threads, @inputset, @toresults, false) }
  #   }

  #   print("\n")
  # }

  print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n")
}

@workers.each { |threads|
  dump_spreadsheet(@poresults, "partialorder", threads)
#  dump_spreadsheet(@toresults, "totalorder", threads)
}
