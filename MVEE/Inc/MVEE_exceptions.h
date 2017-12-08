/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

#ifndef MVEE_EXCEPTIONS_H_
#define MVEE_EXCEPTIONS_H_

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#include <exception>
#include <iomanip>
#include <stdlib.h>
#include "MVEE_logging.h"

/*-----------------------------------------------------------------------------
    MVEE Exceptions
-----------------------------------------------------------------------------*/
class MVEEBaseException: public std::exception
{
public:
	int         variantnum;
	std::string err_string;

	MVEEBaseException()
	{
		variantnum = 0;
	}

    MVEEBaseException(int _variantnum)
	{
		variantnum = _variantnum;
	}

	virtual const char* what() const noexcept
	{
		return err_string.c_str();
	}

	void add_pidstr(std::stringstream& ss)
	{
		if (mvee::active_monitor && variantnum > 0)
			ss << mvee::active_monitor->call_get_variant_pidstr(variantnum) << " - ";
		else
			ss << "Variant: ?? [PID:" << std::setw(5) << std::setfill('0') << abs(variantnum) << std::setw(0) << "] - ";
	}
};

class WaitFailure: public MVEEBaseException
{
public:
	WaitFailure(int _variantnum, const char* when, interaction::mvee_wait_status status)
	{
		variantnum = _variantnum;
		std::stringstream ss;
		
		add_pidstr(ss);

		ss << "Wait failed - when: "
		   << when
		   << " - errno: "
		   << getTextualErrno(errno)
		   << " - wait status: "
		   << getTextualMVEEWaitStatus(status);

		err_string = ss.str();
	}
};

class ResumeFailure: public MVEEBaseException
{
public:
	ResumeFailure(int _variantnum, const char* when)
	{
		variantnum = _variantnum;
		std::stringstream ss;

		add_pidstr(ss);

		ss << "Resume failed - when: "
		   << when
		   << " - errno: "
		   << getTextualErrno(errno);

		err_string = ss.str();
	}
};

class RwRegsFailure: public MVEEBaseException
{
public:
	RwRegsFailure(int _variantnum, const char* when)
	{
		variantnum = _variantnum;
		std::stringstream ss;

		add_pidstr(ss);

		ss << "Reading/Writing registers failed - when: "
		   << when
		   << " - errno: "
		   << getTextualErrno(errno);

		err_string = ss.str();
	}
};

class RwInfoFailure: public MVEEBaseException
{
public:
	RwInfoFailure(int _variantnum, const char* when)
	{
		variantnum = _variantnum;
		std::stringstream ss;

		add_pidstr(ss);

		ss << "Reading/Writing ptrace info failed - when: "
		   << when
		   << " - errno: "
		   << getTextualErrno(errno);

		err_string = ss.str();
	}
};

class RwMemFailure: public MVEEBaseException
{
public:
	RwMemFailure(int _variantnum, const char* when)
	{
		variantnum = _variantnum;
		std::stringstream ss;

		add_pidstr(ss);
		
		ss << "Reading/Writing memory failed - when: "
		   << when
		   << " - errno: "
		   << getTextualErrno(errno);
		
		err_string = ss.str();
	}
};

class AttachFailure: public MVEEBaseException
{
public:
	AttachFailure(int _variantnum)
	{
		variantnum = _variantnum;
		std::stringstream ss;

		add_pidstr(ss);

		ss << "Attach failed - errno: "
		   << getTextualErrno(errno);

		err_string = ss.str();
	}
};

class DetachFailure: public MVEEBaseException
{
public:
	DetachFailure(int _variantnum, const char* when)
	{
		variantnum = _variantnum;
		std::stringstream ss;

		add_pidstr(ss);

		ss << " - Detach failed - when: "
		   << when
		   << " - errno: "
		   << getTextualErrno(errno);
		
		err_string = ss.str();
	}
};

class SignalFailure: public MVEEBaseException
{
public:
	SignalFailure(int _variantnum, int signal)
	{
		variantnum = _variantnum;
		std::stringstream ss;

		add_pidstr(ss);

		ss << " - Signal delivery failed - signal: "
		   << getTextualSig(signal)
		   << " - errno: "
		   << getTextualErrno(errno);
		
		err_string = ss.str();
	}
};


#endif // !MVEE_EXCEPTIONS_H_
