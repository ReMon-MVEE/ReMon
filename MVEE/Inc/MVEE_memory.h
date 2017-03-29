/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

#ifndef MVEE_MEMORY_H_INCLUDED
#define MVEE_MEMORY_H_INCLUDED

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#include <typeinfo>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <utime.h>
#include <sys/time.h>
#include "MVEE_build_config.h"
#include "MVEE_interaction.h"

/*-----------------------------------------------------------------------------
  Function prototypes for raw read/copy operations between the monitor and
  the variants
-----------------------------------------------------------------------------*/
namespace rw
{

//
// Functions for direct copying from 1 process to another
//
	long           copy_data            (pid_t source_pid, void* source_addr, pid_t dest_pid, void* dest_addr, ssize_t len);
	bool           copy_string          (pid_t source_pid, void* source_addr, pid_t dest_pid, void* dest_addr);

//
// Functions for reading from/writing to a child's VA
//
	bool           write_data           (pid_t variantpid, void* addr, ssize_t datalength, void* databuf);
	unsigned char* read_data            (pid_t variantpid, void* addr, ssize_t datalength, int append_zero_byte=0);
	std::string    read_string          (pid_t variantpid, void* addr, ssize_t maxlength=0);
	bool           read_struct          (pid_t variantpid, void* addr, ssize_t datalength, void* buf);

}


/*-----------------------------------------------------------------------------
    ptrace always reads/writes long values but sometimes we want to write
	smaller values. These templates provide a convenient API for reading and
	writing primitive values.
-----------------------------------------------------------------------------*/
union mvee_word
{
    unsigned long  _ulong;
    long           _long;
    unsigned int   _uint;
    int            _int;
    unsigned short _ushort;
    short          _short;
    unsigned char  _uchar;
    char           _char;
};

//
// Helper funcs
//
namespace rw
{
	template<typename T> static void mvee_word_set_field(mvee_word& word, T value) {}
	template<> void mvee_word_set_field<unsigned char>  (mvee_word& word, unsigned char value)  { word._uchar  = value; }
	template<> void mvee_word_set_field<char>           (mvee_word& word, char value)           { word._char   = value; }
	template<> void mvee_word_set_field<unsigned short> (mvee_word& word, unsigned short value) { word._ushort = value; }
	template<> void mvee_word_set_field<short>          (mvee_word& word, short value)          { word._short  = value; }
	template<> void mvee_word_set_field<unsigned int>   (mvee_word& word, unsigned int value)   { word._uint   = value; }
	template<> void mvee_word_set_field<int>            (mvee_word& word, int value)            { word._int    = value; }
	template<> void mvee_word_set_field<unsigned long>  (mvee_word& word, unsigned long value)  { word._ulong  = value; }
	template<> void mvee_word_set_field<long>           (mvee_word& word, long value)           { word._long   = value; }

	template<typename T> static T mvee_word_get_field(mvee_word& word) { return 0; }
	template<> unsigned char  mvee_word_get_field<unsigned char>  (mvee_word& word) { return word._uchar;  }
	template<> char           mvee_word_get_field<char>           (mvee_word& word) { return word._char;   }
	template<> unsigned short mvee_word_get_field<unsigned short> (mvee_word& word) { return word._ushort; }
	template<> short          mvee_word_get_field<short>          (mvee_word& word) { return word._short;  }
	template<> unsigned int   mvee_word_get_field<unsigned int>   (mvee_word& word) { return word._uint;   }
	template<> int            mvee_word_get_field<int>            (mvee_word& word) { return word._int;    }
	template<> unsigned long  mvee_word_get_field<unsigned long>  (mvee_word& word) { return word._ulong;  }
	template<> long           mvee_word_get_field<long>           (mvee_word& word) { return word._long;   }

//
// Writing a primitive typed variable to the address space of a variant
//
	template<typename T> static bool write_primitive(pid_t variantpid, void* addr, T value)
	{
		mvee_word word;
		if (!interaction::read_memory_word(variantpid, addr, word._long))
			return false;
		mvee_word_set_field<T> (word, value);
		if (!interaction::write_memory_word(variantpid, addr, mvee_word_get_field<long>(word)))
			return false;
		return true;
	}

	template<> bool write_primitive<long>(pid_t variantpid, void* addr, long value)
	{
		return interaction::write_memory_word(variantpid, addr, value);
	}

	template<> bool write_primitive<unsigned long>(pid_t variantpid, void* addr, unsigned long value)
	{
		return interaction::write_memory_word(variantpid, addr, (long) value);
	}

//
// Reading a primitive typed variable from the address space of a variant 
//
	template<typename T> static bool read_primitive(pid_t variantpid, void* addr, T& value)
	{
		mvee_word word;	
		if (!interaction::read_memory_word(variantpid, addr, word._long))
			return false;
		value = mvee_word_get_field<T>(word);
		return true;
	}

/*-----------------------------------------------------------------------------
  Specialized reading operations
-----------------------------------------------------------------------------*/
	template<typename T> static bool read(pid_t variantpid, void* addr, T& value)
	{
		if (!addr || !read_struct(variantpid, addr, sizeof(T), &value))
		{
			warnf("Could not read %s\n", typeid(T).name());
			return false;
		}
		return true;
	}

	template<> bool read<struct utimbuf>(pid_t variantpid, void* addr, struct utimbuf& value)
	{
		if (!addr)
		{
			value.actime = value.modtime = time(NULL);
		}
		else
		{
			if (!read_struct(variantpid, addr, sizeof(struct utimbuf), &value))
			{
				warnf("Couldn't read utimbuf\n");
				return false;
			}
		}

		return true;
	}

/*-----------------------------------------------------------------------------
  Specialized writing operations
-----------------------------------------------------------------------------*/
	template<typename T> static bool write(pid_t variantpid, void* addr, T& value)
	{
		return write_data(variantpid, addr, sizeof(T), &value);
	}
}


#endif // MVEE_MEMORY_H_INCLUDED
