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
				m_rangesToSkip.pop_front();
			}

			m_begin += t;
			m_length -= t;
			m_currentMessageBytes += t;
			m_totalBytes += t;
		}
		else
		{
			FILTER_OUTPUT_MAYBE_MODIFIABLE(2, m_begin, m_length, messageEnd, modifiable);

			m_currentMessageBytes += m_length;
			m_totalBytes += m_length;
			m_length = 0;

			if (messageEnd)
			{
				m_currentMessageBytes = 0;
				m_currentSeriesMessages++;
				m_totalMessages++;
				messageEnd = false;
			}
		}
	}

	FILTER_END_NO_MESSAGE_END;
}

size_t MeterFilter::Put2(const byte *begin, size_t length, int messageEnd, bool blocking)
{
	return PutMaybeModifiable(const_cast<byte *>(begin), length, messageEnd, blocking, false);
}

size_t MeterFilter::PutModifiable2(byte *begin, size_t length, int messageEnd, bool blocking)
{
	return PutMaybeModifiable(begin, length, messageEnd, blocking, true);
}

bool MeterFilter::IsolatedMessageSeriesEnd(bool blocking)
{
	m_currentMessageBytes = 0;
	m_currentSeriesMessages = 0;
	m_totalMessageSeries++;
	return false;
}

// *************************************************************

void FilterWithBufferedInput::BlockQueue::ResetQueue(size_t blockSize, size_t maxBlocks)
{
	m_buffer.New(blockSize * maxBlocks);
	m_blockSize = blockSize;
	m_maxBlocks = maxBlocks;
	m_size = 0;
	m_begin = m_buffer;
}

byte *FilterWithBufferedInput::BlockQueue::GetBlock()
{
	if (m_size >= m_blockSize)
	{
		byte *ptr = m_begin;
		if ((m_begin+=m_blockSize) == m_buffer.end())
			m_begin = m_buffer;
		m_size -= m_blockSize;
		return ptr;
	}
	else
		return NULL;
}

byte *FilterWithBufferedInput::BlockQueue::GetContigousBlocks(size_t &numberOfBytes)
{
	numberOfBytes = STDMIN(numberOfBytes, STDMIN(size_t(m_buffer.end()-m_begin), m_size));
	byte *ptr = m_begin;
	m_begin += numberOfBytes;
	m_size -= numberOfBytes;
	if (m_size == 0 || m_begin == m_buffer.end())
		m_begin = m_buffer;
	return ptr;
}

size_t FilterWithBufferedInput::BlockQueue::GetAll(byte *outString)
{
	size_t size = m_size;
	size_t numberOfBytes = m_maxBlocks*m_blockSize;
	const byte *ptr = GetContigousBlocks(numberOfBytes);
	memcpy(outString, ptr, numberOfBytes);
	memcpy(outString+numberOfBytes, m_begin, m_size);
	m_size = 0;
	return size;
}

void FilterWithBufferedInput::BlockQueue::Put(const byte *inString, size_t length)
{
	assert(m_size + length <= m_buffer.size());
	byte *end = (m_size < size_t(m_buffer.end()-m_begin)) ? m_begin + m_size : m_begin + m_size - m_buffer.size();
	size_t len = STDMIN(length, size_t(m_buffer.end()-end));
	memcpy(end, inString, len);
	if (len < length)
		memcpy(m_buffer, inString+len, length-len);
	m_size += length;
}

FilterWithBufferedInput::FilterWithBufferedInput(BufferedTransformation *attachment)
	: Filter(attachment)
{
}

FilterWithBufferedInput::FilterWithBufferedInput(size_t firstSize, size_t blockSize, size_t lastSize, BufferedTransformation *attachment)
	: Filter(attachment), m_firstSize(firstSize), m_blockSize(blockSize), m_lastSize(lastSize)
	, m_firstInputDone(false)
{
	if (m_firstSize < 0 || m_blockSize < 1 || m_lastSize < 0)
		throw InvalidArgument("FilterWithBufferedInput: invalid buffer size");

	m_queue.ResetQueue(1, m_firstSize);
}

void FilterWithBufferedInput::IsolatedInitialize(const NameValuePairs &parameters)
{
	InitializeDerivedAndReturnNewSizes(parameters, m_firstSize, m_blockSize, m_lastSize);
	if (m_firstSize < 0 || m_blockSize < 1 || m_lastSize < 0)
		throw InvalidArgument("FilterWithBufferedInput: invalid buffer size");
	m_queue.ResetQueue(1, m_firstSize);
	m_firstInputDone = false;
}

bool FilterWithBufferedInput::IsolatedFlush(bool hardFlush, bool blocking)
{
	if (!blocking)
		throw BlockingInputOnly("FilterWithBufferedInput");
	
	if (hardFlush)
		ForceNextPut();
	FlushDerived();
	
	return false;
}

size_t FilterWithBufferedInput::PutMaybeModifiable(byte *inString, size_t length, int messageEnd, bool blocking, bool modifiable)
{
	if (!blocking)
		throw BlockingInputOnly("FilterWithBufferedInput");

	if (length != 0)
	{
		size_t newLength = m_queue.CurrentSize() + length;

		if (!m_firstInputDone && newLength >= m_firstSize)
		{
			size_t len = m_firstSize - m_queue.CurrentSize();
			m_queue.Put(inString, len);
			FirstPut(m_queue.GetContigousBlocks(m_firstSize));
			assert(m_queue.CurrentSize() == 0);
			m_queue.ResetQueue(m_blockSize, (2*m_blockSize+m_lastSize-2)/m_blockSize);

			inString += len;
			newLength -= m_firstSize;
			m_firstInputDone = true;
		}

		if (m_firstInputDone)
		{
			if (m_blockSize == 1)
			{
				while (newLength > m_lastSize && m_queue.CurrentSize() > 0)
				{
					size_t len = newLength - m_lastSize;
					byte *ptr = m_queue.GetContigousBlocks(len);
					NextPutModifiable(ptr, len);
					newLength -= len;
				}

				if (newLength > m_lastSize)
				{
					size_t len = newLength - m_lastSize;
					NextPutMaybeModifiable(inString, len, modifiable);
					inString += len;
					newLength -= len;
				}
			}
			else
			{
				while (newLength >= m_blockSize + m_lastSize && m_queue.CurrentSize() >= m_blockSize)
				{
					NextPutModifiable(m_queue.GetBlock(), m_blockSize);
					newLength -= m_blockSize;
				}

				if (newLength >= m_blockSize + m_lastSize && m_queue.CurrentSize() > 0)
				{
					assert(m_queue.CurrentSize() < m_blockSize);
					size_t len = m_blockSize - m_queue.CurrentSize();
					m_queue.Put(inString, len);
					inString += len;
					NextPutModifiable(m_queue.GetBlock(), m_blockSize);
					newLength -= m_blockSize;
				}

				if (newLength >= m_blockSize + m_lastSize)
				{
					size_t len = RoundDownToMultipleOf(newLength - m_lastSize, m_blockSize);
					NextPutMaybeModifiable(inString, len, modifiable);
					inString += len;
					newLength -= len;
				}
			}
		}

		m_queue.Put(inString, newLength - m_queue.CurrentSize());
	}

	if (messageEnd)
	{
		if (!m_firstInputDone && m_firstSize==0)
			FirstPut(NULL);

		SecByteBlock temp(m_queue.CurrentSize());
		m_queue.GetAll(temp);
		LastPut(temp, temp.size());

		m_firstInputDone = false;
		m_queue.ResetQueue(1, m_firstSize);

		Output(1, NULL, 0, messageEnd, blocking);
	}
	return 0;
}

void Filter