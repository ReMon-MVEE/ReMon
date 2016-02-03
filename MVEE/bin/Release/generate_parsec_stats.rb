#!/usr/bin/env ruby

@parsec  = [80, 81, 83, 85, 86, 87, 88, 89, 90, 91, 92]
@workers = (1..8)
@input    = "native"

def get_bench_name(benchnum)
  benchname=`grep "case #{benchnum}:" -A8 ../../Src/MVEE_demos.cpp | grep parsec\_bench | head -n1`.split("\"")[1]  
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

def install_partialorder_libc()
  print("Installing GHUMVEE partial order eglibc 2.19\n")
  orig = Dir.pwd
  Dir.chdir(File.expand_path("~/eglibc-builds/eglibc-mvee-partialorder-nodebugging"))
  `sudo dpkg -i libc6_2.19-0ubuntu6_amd64.deb libc6-dbg_2.19-0ubuntu6_amd64.deb libc-bin_2.19-0ubuntu6_amd64.deb multiarch-support_2.19-0ubuntu6_amd64.deb`
  Dir.chdir(orig)
end

`rm -rf Logs`
`mkdir Logs`

@workers.each { |threads|
  print("#{threads} workers\n")
  @parsec.each { |num|
    run_bench(num, threads)
  }
}
