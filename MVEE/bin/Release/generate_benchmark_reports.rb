#!/usr/bin/env ruby
# run generate_spec_stats.rb or generate_parsec_stats.rb before this!!!

def to_si(bytes)
  return "#{Float(bytes) / 1000000000000.0} TB" if bytes > 1000000000000
  return "#{Float(bytes) / 1000000000.0} GB" if bytes > 1000000000
  return "#{Float(bytes) / 1000000.0} MB" if bytes > 1000000
  return "#{Float(bytes) / 1000.0} kB" if bytes > 1000
  bytes
end

def check_folder(line)
  # system calls dispatched as master calls (i.e. only the master replica
  # executes them and the MVEE replicates the results)
  mastercalls = 0
  # system calls dispatched as normal calls (i.e. all replicae execute them but
  # the replicae may only enter the kernel if they are all synced)
  normalcalls = 0
  # system calls dispatched as unsynced calls (i.e. the replica executing the call
  # does not have to wait at a rendez-vous point)
  unsyncedcalls = 0
  # threads created by the replicae
  threads = 0
  # number of rdtsc instructions we've intercepted. We intercept these because
  # they can introduce inconsistencies.
  rdtsc = 0
  # signals intercepted by the monitor. The ptracer ALWAYS gets a notification
  # when a signal is sent to one of its tracees
  sigreceived = 0
  # signals actually delivered. Many signals do not get delivered because they
  # are blocked or ignored
  sigdelivered = 0
  # native execution time
  native = `cat #{line.chop}/MVEE_native.log`.chop.to_f

  print("================================================================================\n")
  print("stats for: #{line.chop}\n")
  print("================================================================================\n")

  `cat #{line.chop}/MVEE.log`.each_line { |ln|
    mastercalls += 1 if ln.include? " as mastercall"
    normalcalls += 1 if ln.include? " as normal"
    unsyncedcalls += 1 if ln.include? "nonsynced"
    threads += 1 if ln.include? "Spawned child"
    rdtsc += 1 if ln.include? "the rdtsc"
    sigreceived += 1 if ln.match(/Signal.*received/)
    sigdelivered += 1 if ln.match(/Signal.*delivered/)
  }

  # we assume that we're checking the log of a run with 2 replicae. Thus, all of these
  # will be in the log twice
  unsyncedcalls /= 2
  rdtsc /= 2
  sigreceived /= 2

  print("syscall statistics:\n")
  print("    > total system calls: #{mastercalls+normalcalls+unsyncedcalls}\n")
  print("    > master calls: #{mastercalls}\n")
  print("    > normal calls: #{normalcalls}\n")
  print("    > unsynced calls: #{unsyncedcalls}\n\n")

  print("signal statistics:\n")
  print("    > signals received: #{sigreceived}\n")
  print("    > signals delivered: #{sigdelivered}\n\n")

  print("miscellaneous events:\n")
  print("    > threads created: #{threads}\n")
  print("    > rdtsc instrs executed: #{rdtsc}\n")
  print("================================================================================\n")

  ops_per_type = Hash.new
  bytes_per_type = Hash.new

  `cat #{line.chop}/MVEE_datatransfer.log`.each_line { |ln|
    arr = ln.split(" ")
    ops_per_type[arr[0]] = 0 if not ops_per_type[arr[0]]
    ops_per_type[arr[0]]+=1
    bytes_per_type[arr[0]] = 0 if not bytes_per_type[arr[0]]
    bytes_per_type[arr[0]]+=arr[1].to_i
  }

  total = 0
  bytes_per_type.each_value { |val|
    total += val
  }
  totalops = 0
  ops_per_type.each_value { |val|
    totalops += val
  }

  print("datatransfer statistics:\n")
  print("    > total bytes transferred by the monitor: #{total} (#{to_si(total)})\n")
  print("    > total datatransfer ops performed by the monitor: #{totalops}\n")
  print("    > datatransfer ops per type:\n #{ops_per_type}\n\n")
  print("    > bytes transferred per type:\n #{bytes_per_type}\n")
  print("================================================================================\n")

  # total number of atomic operations we've replicated. Note that atomic operations do not
  # get replicated while the replicae are single threaded!
  total_atomic_ops = 0
  # total number of individual memory words involved in the replication
  total_atomic_words = 0
  # approximate number of times the cache line with the queue position has been invalidated
  # in the master replica. This cache line gets invalidated when operation n+1 is performed
  # by a different thread than operation n
  #
  # I've called this the "bounce count" but I'm guessing there's a much better and more 
  # accurate term for this!
  bounce_count = 0

  `cat #{line.chop}/MVEE_lockstats.log`.each_line { |ln|
    total_atomic_ops   += ln.chop.split(" ")[-1].to_i if ln.match(/Total number of operations/)
    total_atomic_words += ln.chop.split(" ")[-1].to_i if ln.match(/Total number of individual/)
    bounce_count       += ln.chop.split(" ")[-1].to_i if ln.match(/Bounce count/)
  }

  print("synchronization statistics:\n")
  print("    > total number of atomic operations: #{total_atomic_ops}\n")
  print("    > total number of individual atomic words: #{total_atomic_words}\n")
  print("    > bounce count: #{bounce_count}\n")
  print("    > bounce density: #{Float(bounce_count)/Float(total_atomic_ops)}\n") if total_atomic_ops > 0
  print("================================================================================\n\n\n")

  File.open("Reports/#{line.chop.split("/")[-1]}.csv", "w") { |file|
    file.write("benchname;native;total syscalls;master calls;normal calls;unsynced calls;signals received;signals delivered;threads created;rdtsc instrs intercepted;datatransfer bytes;datatransfer ops;atomic ops;syscall density; transfer op density; transfer byte density; atomic op density; bounce density;\n")
    file.write("#{line.chop.split("/")[-1]};#{native.to_s.gsub(".", ",")};#{mastercalls+normalcalls+unsyncedcalls};#{mastercalls};#{normalcalls};#{unsyncedcalls};#{sigreceived};#{sigdelivered};#{threads};#{rdtsc};#{total};#{totalops};#{total_atomic_ops};#{((mastercalls+normalcalls+unsyncedcalls)/native).to_s.gsub(".", ",")};#{(totalops/native).to_s.gsub(".", ",")};#{(total/native).to_s.gsub(".", ",")};#{(total_atomic_ops/native).to_s.gsub(".", ",")};#{(bounce_count/native).to_s.gsub(".", ",")}\n")
  }
  
  File.open("Reports/Full_Report.csv", "a") { |file|
    file.write("benchname;native;total syscalls;master calls;normal calls;unsynced calls;signals received;signals delivered;threads created;rdtsc instrs intercepted;datatransfer bytes;datatransfer ops;atomic ops;syscall density; transfer op density; transfer byte density; atomic op density; bounce density;\n") if file.size == 0
    file.write("#{line.chop.split("/")[-1]};#{native.to_s.gsub(".", ",")};#{mastercalls+normalcalls+unsyncedcalls};#{mastercalls};#{normalcalls};#{unsyncedcalls};#{sigreceived};#{sigdelivered};#{threads};#{rdtsc};#{total};#{totalops};#{total_atomic_ops};#{((mastercalls+normalcalls+unsyncedcalls)/native).to_s.gsub(".", ",")};#{(totalops/native).to_s.gsub(".", ",")};#{(total/native).to_s.gsub(".", ",")};#{(total_atomic_ops/native).to_s.gsub(".", ",")};#{(bounce_count/native).to_s.gsub(".", ",")}\n")
  }

end

`mkdir -p Reports`
`find Logs/* -type d`.each_line { |line|
  check_folder(line)
}

