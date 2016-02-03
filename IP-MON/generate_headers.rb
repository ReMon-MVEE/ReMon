#!/usr/bin/env ruby

@syscalls      = Hash.new    # maps syscall number onto syscall name
@unchecked     = Array.new   # all of the calls we may possibly allow to go through unchecked
@unsynced      = Array.new
@maybe_checked = Array.new
@calcsize      = Array.new
@precall       = Array.new
@postcall      = Array.new

def md5(file)
  ret=`md5sum #{file} | cut -d' ' -f1`
end

def replace_if_different(oldfile, newfile)
  if (not File.exists?(oldfile)) or (md5(oldfile) != md5(newfile))
    print("#{oldfile} > File has changed.\n")
    `mv #{newfile} #{oldfile}`
  else
    print("#{oldfile} > File has not changed.\n")
    `rm #{newfile}`
  end
end

def write_header(arr, header, args, prefix, suffix)
  File.open("MVEE_ipmon_#{header}.tmp", 'w') { |file|
    arr.each { |handler|
      if @unchecked.include? handler
        file.write("case __NR_#{handler}: #{prefix} ipmon_handle_#{handler}_#{header}(#{args}); #{suffix}\n")
      end
    }
  }

  replace_if_different("MVEE_ipmon_#{header}.h", "MVEE_ipmon_#{header}.tmp")
end

def add_to_array(arr, line, handler)
  if line.match(/handle.*#{handler}.*\(/) and not line.match(/case [[:digit:]]+/)
    arr << line.gsub(/_#{handler}.*/, "").gsub(/.*handle_/, "").rstrip
  end
end

File.open("/usr/include/x86_64-linux-gnu/asm/unistd_64.h").each { |line|
  if line.match(/^#define.*__NR_[[:graph:]]*[[:digit:]]*/)
    callnum = line.split(" ")[-1]
    callname = line.split(" ")[-2].gsub("__NR_","")
    @syscalls[callnum] = callname
  end
}

IO.popen("gcc -E MVEE_ipmon.cpp") { |p|
  p.readlines.each { |line|

    add_to_array(@unsynced, line, "is_unsynced")
    add_to_array(@maybe_checked, line, "maybe_checked")
    add_to_array(@calcsize, line, "calcsize")
    add_to_array(@precall, line, "precall")
    add_to_array(@postcall, line, "postcall")

    if line.match(/set_unchecked_syscall/)
      callnum = line.split(",")[-2].lstrip
      unchecked_bit = line.split(",")[-1].split(")")[0].lstrip

      if @syscalls[callnum]
        @unchecked += [@syscalls[callnum]] if unchecked_bit == "1"
        @unchecked -= [@syscalls[callnum]] if unchecked_bit == "0"        
      end
    end    
  }
}

write_header(@unsynced, "is_unsynced", "", "return", "")
write_header(@maybe_checked, "maybe_checked", "args", "return", "")
write_header(@calcsize, "calcsize", "args, args_size, ret_size", "", "break;")
write_header(@precall, "precall", "args, entry_offset", "return", "")
write_header(@postcall, "postcall", "args, entry_offset, ret, success", "return", "")

