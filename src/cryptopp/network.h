#ifndef CRYPTOPP_NETWORK_H
#define CRYPTOPP_NETWORK_H

#include "config.h"

#ifdef HIGHRES_TIMER_AVAILABLE

#include "filters.h"
#include "hrtimer.h"

#include <deque>

NAMESPACE_BEGIN(CryptoPP)

class LimitedBandwidth
{
public:
	LimitedBandwidth(lword maxBytesPerSecond = 0)
		: m_maxBytesPerSecond(maxBytesPerSecond), m_timer(Timer::MILLISECONDS)
		, m_nextTransceiveTime(0)
		{ m_timer.StartTimer(); }

	lword GetMaxBytesPerSecond() const
		{ return m_maxBytesPerSecond; }

	void SetMaxBytesPerSecond(lword v)
		{ m_maxBytesPerSecond = v; }

	lword ComputeCurrentTransceiveLimit();

	double TimeToNextTransceive();

	void NoteTransceive(lword size);

public:
	/*! GetWaitObjects() must be called despite the 0 return from GetMaxWaitObjectCount();
	    the 0 is because the ScheduleEvent() method is used instead of adding a wait object */
	unsigned int GetMaxWaitObjectCount() const { return 0; }
	void GetWaitObjects(WaitObjectContainer &container, const CallStack &callStack);

private:	
	lword m_maxBytesPerSecond;

	typedef std::deque<std::pair<double, lword> > OpQueue;
	OpQueue m_ops;

	Timer m_timer;
	double m_nextTransceiveTime;

	void ComputeNextTransceiveTime();
	double GetCurTimeAndCleanUp();
};

//! a Source class that can pump from a device for a specified amount of time.
class CRYPTOPP_NO_VTABLE NonblockingSource : public AutoSignaling<Source>, public LimitedBandwidth
{
public:
	NonblockingSource(BufferedTransformation *attachment)
		: m_messageEndSent(false) , m_doPumpBlocked(false), m_blockedBySpeedLimit(false) {Detach(attachment);}

	//!	\name NONBLOCKING SOURCE
	//@{

	//! pump up to maxSize bytes using at most maxTime milliseconds
	/*! If checkDelimiter is true, pump up to delimiter, which itself is not extracted or pumped. */
	size_t GeneralPump2(lword &byteCount, bool blockingOutput=true, unsigned long maxTime=INFINITE_TIME, bool checkDelimiter=false, byte delimiter='\n');

	lword GeneralPump(lword maxSize=LWORD_MAX, unsigned long maxTime=INFINITE_TIME, bool checkDelimiter=false, byte delimiter='\n')
	{
		GeneralPump2(maxSize, true, maxTime, checkDelimiter, delimiter);
		return maxSize;
	}
	lword TimedPump(unsigned long maxTime)
		{return GeneralPump(LWORD_MAX, maxTime);}
	lword PumpLine(byte delimiter='\n', lword maxSize=1024)
		{return GeneralPump(maxSize, INFINITE_TIME, true, delimiter);}

	size_t Pump2(lword &byteCount, bool blocking=true)
		{return GeneralPump2(byteCount, blocking, blocking ? INFINITE_TIME : 0);}
	size_t PumpMessages2(