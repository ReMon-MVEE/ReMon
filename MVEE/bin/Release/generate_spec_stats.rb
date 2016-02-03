#!/usr/bin/env ruby

def run_bench(benchnum)
  benchname=`grep "case #{benchnum}:" -A8 ../../Src/MVEE_demos.cpp | grep execl | head -n1`.split(",")[2]

  if benchname
    benchname=benchname.match(/[[:digit:]]{3}.[[:alnum:]]*/)
    print("running benchmark: #{benchname}\n")
    `./MVEE #{benchnum} 2`

    `mkdir -p Logs/#{benchname}`
    `mv Logs/*.log Logs/#{benchname}`

    `./MVEE #{benchnum} 1 -n 2>&1`.each_line { |ln|
      if ln.match(/after: [[:digit:]]+\.[[:digit:]]+ seconds/)
        seconds = ln.chop.split(" ")[-2]
        `echo "#{seconds}" > Logs/#{benchname}/MVEE_native.log`
      end
    }

    `rm Logs/*.log`
  end
end

def run_suite(suite)
  suite.each { |num|
    run_bench(num)
  }
end

specint=(60..72).to_a
specfp=(118..133).to_a

`rm -rf Logs`
`mkdir Logs`

run_suite(specint)
run_suite(specfp)
