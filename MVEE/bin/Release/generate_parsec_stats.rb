#!/usr/bin/env ruby

@parsec  = (30..42)
@workers = (1..8)
@input    = "native"

def get_bench_name(benchnum)
  _benchname=`grep "REGISTER.*(#{benchnum}," ../../Src/MVEE_demos.cpp`.split('"')[3]
  return _benchname if _benchname
  "dunno"
end

def run_bench(benchnum, threads)
  benchname = get_bench_name(benchnum)
  return if not benchname
  print("running benchmark: #{benchname}\n")
  `./MVEE #{benchnum} 2 #{threads} #{@input}`
  
  `mkdir -p Logs/#{benchname}_#{threads}_workers`
  `mv Logs/*.log Logs/#{benchname}_#{threads}_workers`

  `./MVEE #{benchnum} 1 #{threads} #{@input} -n`.each_line { |ln|
    if ln.match(/real\t/)
      time = ln.split("\t")[1].chop 
      seconds = Float(time.split("m")[0].to_i * 60) + Float(time.split("m")[1].chop)

      `echo "#{seconds}" > Logs/#{benchname}_#{threads}_workers/MVEE_native.log`
    end
  }
  
  `rm Logs/*.log`
end

`rm -rf Logs`
`mkdir Logs`

@workers.each { |threads|
  print("#{threads} workers\n")
  @parsec.each { |num|
    run_bench(num, threads)
  }
}
