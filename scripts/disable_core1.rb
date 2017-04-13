#!/usr/bin/env ruby

processorid=0

`cat /proc/cpuinfo`.each_line { |line|
  processorid=line.split(": ")[1].chomp  if line.start_with? "processor"

  if line.start_with? "physical id" then
    id=line.split(": ")[1].chomp

    if id == "1" then
      print("Disabling core #{processorid}...\n")
      `echo 0 > /sys/devices/system/cpu/cpu#{processorid}/online`
    end
  end
}
