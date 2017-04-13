#!/usr/bin/env ruby

processorid=0

`find /sys/devices/system/cpu/* | grep online | grep -v "/cpu/online"`.each_line { |line|
  processorid=line.split("/")[-2].split("cpu")[1]

  if `cat /sys/devices/system/cpu/cpu#{processorid}/online`.chomp == "0"
  then
    print("Enabling core #{processorid}...\n")
    `echo 1 > /sys/devices/system/cpu/cpu#{processorid}/online`
  end
}
