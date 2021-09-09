// filters.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"

#ifndef CRYPTOPP_IMPORTS

#include "filters.h"
#include "mqueue.h"
#include "fltrimpl.h"
#include "argnames.h"
#include <memory>
#include <functional>

NAMESPACE_BEGIN(CryptoPP)

Filter::Filter(BufferedTransformation *attachment)
	: m_attachment(attachment), m_continueAt(0)
{
}

BufferedTransformation * Filter::NewDefaultAttachment() const
{
	return new MessageQueue;
}

BufferedTransformation * Filter::AttachedTransformation()
{
	if (m_attachment.get() == NULL)
		m_attachment.reset(NewDefaultAttachment());
	return m_attachment.get();
}

const BufferedTransformation *Filter::AttachedTransformation() const
{
	if (m_attachment.get() == NULL)
		const_cast<Filter *>(this)->m_attachment.reset(NewDefaultAttachment());
	return m_attachment.get();
}

void Filter::Detach(BufferedTransformation *newOut)
{
	m_attachment.reset(newOut);
}

void Filter::Insert(Filter *filter)
{
	filter->m_attachment.reset(m_attachment.release());
	m_attachment.reset(filter);
}

size_t Filter::CopyRangeTo2(BufferedTransformation &target, lword &begin, lword end, const std::string &channel, bool blocking) const
{
	return AttachedTransformation()->CopyRangeTo2(target, begin, end, channel, blocking);
}

size_t Filter::TransferTo2(BufferedTransformation &target, lword &transferBytes, const std::string &channel, bool blocking)
{
	return AttachedTransformation()->TransferTo2(target, transferBytes, channel, blocking);
}

void Filter::Initialize(const NameValuePairs &parameters, int propagation)
{
	m_continueAt = 0;
	IsolatedInitialize(parameters);
	PropagateInitialize(parameters, propagation);
}

bool Filter::Flush(bool hardFlush, int propagation, bool blocking)
{
	switch (m_continueAt)
	{
	case 0:
		if (IsolatedFlush(hardFlush, blocking))
			return true;
	case 1:
		if (OutputFlush(1, hardFlush, propagation, blocking))
			return true;
	}
	return false;
}

bool Filter::MessageSeriesEnd(int propagation, bool blocking)
{
	switch (m_continueAt)
	{
	case 0:
		if (IsolatedMessageSeriesEnd(blocking))
			return true;
	case 1:
		if (ShouldPropagateMessageSeriesEnd() && OutputMessageSeriesEnd(1, propagation, blocking))
			return true;
	}
	return false;
}

void Filter::PropagateInitialize(const NameValuePairs &parameters, int propagation)
{
	if (propagation)
		AttachedTransformation()->Initialize(parameters, propagation-1);
}

size_t Filter::OutputModifiable(int outputSite, byte *inString, size_t length, int messageEnd, bool blocking, const std::string &channel)
{
	if (messageEnd)
		messageEnd--;
	size_t result = AttachedTransformation()->ChannelPutModifiable2(channel, inString, length, messageEnd, blocking);
	m_continueAt = result ? outputSite : 0;
	return result;
}

size_t Filter::Output(int outputSite, const byte *inString, size_t length, int messageEnd, bool blocking, const std::string &channel)
{
	if (messageEnd)
		messageEnd--;
	size_t result = AttachedTransformation()->ChannelPut2(channel, inString, length, messageEnd, blocking);
	m_continueAt = result ? outputSite : 0;
	return result;
}

bool Filter::OutputFlush(int outputSite, bool hardFlush, int propagation, bool blocking, const std::string &channel)
{
	if (propagation && AttachedTransformation()->ChannelFlush(channel, hardFlush, propagation-1, blocking))
	{
		m_continueAt = outputSite;
		return true;
	}
	m_continueAt = 0;
	return false;
}

bool Filter::OutputMessageSeriesEnd(int outputSite, int propagation, bool blocking, const std::string &channel)
{
	if (propagation && AttachedTransformation()->ChannelMessageSeriesEnd(channel, propagation-1, blocking))
	{
		m_continueAt = outputSite;
		return true;
	}
	m_continueAt = 0;
	return false;
}

// *************************************************************

void MeterFilter::ResetMeter()
{
	m_currentMessageBytes = m_totalBytes = m_currentSeriesMessages = m_totalMessages = m_totalMessageSeries = 0;
	m_rangesToSkip.clear();
}

void MeterFilter::AddRangeToSkip(unsigned int message, lword position, lword size, bool sortNow)
{
	MessageRange r = {message, position, size};
	m_rangesToSkip.push_back(r);
	if (sortNow)
		std::sort(m_rangesToSkip.begin(), m_rangesToSkip.end());
}

size_t MeterFilter::PutMaybeModifiable(byte *begin, size_t length, int messageEnd, bool blocking, bool modifiable)
{
	if (!m_transparent)
		return 0;

	size_t t;
	FILTER_BEGIN;

	m_begin = begin;
	m_length = length;

	while (m_length > 0 || messageEnd)
	{
		if (m_length > 0  && !m_rangesToSkip.empty() && m_rangesToSkip.front().message == m_totalMessages && m_currentMessageBytes + m_length > m_rangesToSkip.front().position)
		{
			FILTER_OUTPUT_MAYBE_MODIFIABLE(1, m_begin, t = (size_t)SaturatingSubtract(m_rangesToSkip.front().position, m_currentMessageBytes), false, modifiable);

			assert(t < m_length);
			m_begin += t;
			m_length -= t;
			m_currentMessageBytes += t;
			m_totalBytes += t;

			if (m_currentMessageBytes + m_length < m_rangesToSkip.front().position + m_rangesToSkip.front().size)
				t = m_length;
			else
			{
				t = (size_t)SaturatingSubtract(m_rangesToSkip.front().position + m_rangesToSkip.front().size, m_currentMessageBytes);
				assert(t <= m_length);
				m_rangesToSk