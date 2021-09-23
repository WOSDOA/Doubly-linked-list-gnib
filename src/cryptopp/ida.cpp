// ida.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "ida.h"

#include "algebra.h"
#include "gf2_32.h"
#include "polynomi.h"
#include <functional>

#include "polynomi.cpp"

ANONYMOUS_NAMESPACE_BEGIN
static const CryptoPP::GF2_32 field;
NAMESPACE_END

using namespace std;

NAMESPACE_BEGIN(CryptoPP)

void RawIDA::IsolatedInitialize(const NameValuePairs &parameters)
{
	if (!parameters.GetIntValue("RecoveryThreshold", m_threshold))
		throw InvalidArgument("RawIDA: missing RecoveryThreshold argument");

	if (m_threshold <= 0)
		throw InvalidArgument("RawIDA: RecoveryThreshold must be greater than 0");

	m_lastMapPosition = m_inputChannelMap.end();
	m_channelsReady = 0;
	m_channelsFinished = 0;
	m_w.New(m_threshold);
	m_y.New(m_threshold);
	m_inputQueues.reserve(m_threshold);

	m_outputChannelIds.clear();
	m_outputChannelIdStrings.clear();
	m_outputQueues.clear();

	word32 outputChannelID;
	if (parameters.GetValue("OutputChannelID", outputChannelID))
		AddOutputChannel(outputChannelID);
	else
	{
		int nShares = parameters.GetIntValueWithDefault("NumberOfShares", m_threshold);
		for (int i=0; i<nShares; i++)
			AddOutputChannel(i);
	}
}

unsigned int RawIDA::InsertInputChannel(word32 channelId)
{
	if (m_lastMapPosition != m_inputChannelMap.end())
	{
		if (m_lastMapPosition->first == channelId)
			goto skipFind;
		++m_lastMapPosition;
		if (m_lastMapPosition != m_inputChannelMap.end() && m_lastMapPosition->first == channelId)
			goto skipFind;
	}
	m_lastMapPosition = m_inputChannelMap.find(channelId);

skipFind:
	if (m_lastMapPosition == m_inputChannelMap.end())
	{
		if (m_inputChannelIds.size() == m_threshold)
			return m_threshold;

		m_lastMapPosition = m_inputChannelMap.insert(InputChannelMap::value_type(channelId, (unsigned int)m_inputChannelIds.size())).first;
		m_inputQueues.push_back(MessageQueue());
		m_inputChannelIds.push_back(channelId);

		if (m_inputChannelIds.size() == m_threshold)
			PrepareInterpolation();
	}
	return m_lastMapPosition->second;
}

unsigned int RawIDA::LookupInputChannel(word32 channelId) const
{
	map<word32, unsigned int>::const_iterator it = m_inputChannelMap.find(channelId);
	if (it == m_inputChannelMap.end())
		return m_threshold;
	else
		return it->second;
}

void RawIDA::ChannelData(word32 channelId, const byte *inString, size_t length, bool messageEnd)
{
	int i = InsertInputChannel(channelId);
	if (i < m_threshold)
	{
		lword size = m_inputQueues[i].MaxRetrievable();
		m_inputQueues[i].Put(inString, length);
		if (size < 4 && size + length >= 4)
		{
			m_channelsReady++;
			if (m_channelsRea