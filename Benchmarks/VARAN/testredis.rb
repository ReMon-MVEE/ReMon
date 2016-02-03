#!/usr/bin/env ruby

@hostname = "localhost"
@total = 0.0

for i in 1..5
  @total = 0.0

  `redis-3.0.3/src/redis-benchmark -h #{@hostname} -p 8080`.each_line { |ln|
    if ln.match(/requests per second/)
      res = ln.split(" ")[0].gsub('.', ',').to_f
      @total += res
    end
  }

  print("#{@total.to_s.gsub(".", ",")}\n")
end

