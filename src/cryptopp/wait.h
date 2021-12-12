#ifndef CRYPTOPP_WAIT_H
#define CRYPTOPP_WAIT_H

#include "config.h"

#ifdef SOCKETS_AVAILABLE

#include "misc.h"
#include "cryptlib.h"
#include <vector>

#ifdef USE_WINDOWS_STYLE_SOCKETS
#include <winsock2.h>
#else
#include <sys/types.h>
#endif

#include "hrtimer.h"

NAMESPACE_BEGIN(CryptoPP)

class Tracer
{
public:
	Tracer(unsigned int level) : m_level(level) {}
	virtual ~Tracer() {}

protected:
	//! Override this in your most-derived tracer to do the actual tracing.
	virtual void Trace(unsigned int n, std::string const& s) = 0;

	/*! By default, tracers will decide which trace messages to trace according to a trace level
		mechanism. If your most-derived tracer uses a different mechanism, override this to
		return false. If this method returns false, the default TraceXxxx(void) methods will all
		return 0 and must be overridden explicitly by your tracer for trace messages you want. */
	virtual bool UsingDefaults() const { return true; }

protected:
	unsigned int m_level;

	void TraceIf(unsigned int n, std::string const&s)
		{ if (n) Trace(n, s); }

	/*! Returns nr if, according to the default log settings mechanism (using log levels),
	    the message should be traced. Returns 0 if the default trace level mechanism is not
		in use, or if it is in use but the event should not be traced. Provided as a utility
		method for easier and shorter coding of default TraceXxxx(void) implementations. */
	unsigned int Tracing(unsigned int nr, unsigned int minLevel) const
		{ return (UsingDefaults() && m_level >= minLevel) ? nr : 0; }
};

// Your Tracer-derived class should inherit as virtual public from Tracer or another
// Tracer-derived class, and should pass the log level in its constructor. You can use the
// following methods to begin and end your Tracer definition.

// This constructor macro initializes Tracer directly even if not derived directly from it;
// this is intended, virtual base classes are always initialized by the most derived class.
#define CRYPTOPP_TRACER_CONSTRUCTOR(DERIVED) \
	public: DERIVED(unsigned int level = 0) : Tracer(level) {}

#define CRYPTOPP_BEGIN_TRACER_CLASS_1(DERIVED, BASE1) \
	class DERIVED : virtual public BASE1 { CRYPTOPP_TRACER_CONSTRUCTOR(DERIVED)

#define CRYPTOPP_BEGIN_TRACER_CLASS_2(DERIVED, BASE1, BASE2) \
	class DERIVED : virtual public BASE1, virtual public BASE2 { CRYPTOPP_TRACER_CONSTRUCTOR(DERIVED)

#define CRYPTOPP_END_TRACER_CLASS };

// In your Tracer-derived class, you should define a globally unique event number for each
// new event defined. This can be done using the following macros.

#define CRYPTOPP_BEGIN_TRACER_EVENTS(UNIQUENR)	enum { EVENTBASE = UNIQUENR,
#define CRYPTOPP_TRACER_EVENT(EVENTNAME)				EventNr_##EVENTNAME,
#define CRYPTOPP_END_TRACER_EVENTS				};

// In your own Tracer-derived class, you must define two methods per new trace event type:
// - unsigned int TraceXxxx() const
//   Your default implementation of this method should return the event number if according
//   to the default trace level system the event should be traced, or 0 if it should not.
// - void TraceXxxx(string const& s)
//   This method should call TraceIf(TraceXxxx(), s); to do the tracing.
// For your convenience, a macro to define these two types of methods are defined below.
// If you use this macro, you should also use the TRACER_EVENTS macros above to associate
// event names with numbers.

#define CRYPTOPP_TRACER_EVENT_METHODS(EVENTNAME, LOGLEVEL) \
	virtual unsigned int Trace##EVENTNAME() const { return Tracing(EventNr_##EVENTNAME, LOGLEVEL); } \
	virtual void Trace##EVENTNAME(std::string const& s) { TraceIf(Trace##EVENTNAME(), s); }


/*! A simple unidirectional linked list with m_prev == 0 to indicate the final entry.
    The aim of this implementation is to provide a very lightweight and practical
	tracing mechanism with a low performance impact. Functions and methods supporting
	this call-stack mechanism would take a parameter of the form "CallStack const& callStack",
	and would pass this parameter to subsequent functions they call using the construct:

	SubFunc(arg1, arg2, CallStack("my func at place such and such", &callStack));
	
	The advantage of this approach is that it is easy to use and should be very efficient,
	involving no allocation from the heap, just a linked list of stack objects containing
	pointers to static ASCIIZ strings (or possibly additional but simple data if deriv