#include "stdafx.h"
#include "PacketPool.h"

PacketPool::PacketPool()
{
}


PacketPool::~PacketPool()
{
}

/**
*	@brief	������ݰ�����
*	@param	pkt_data	���ݰ�
*	@param	header		�ײ�
*	@return	-
*/
void PacketPool::add(const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	if (header && pkt_data)
	{
		int pktNum = 1 + m_pkts.size();
		Packet pkt(header, pkt_data, pktNum);
		m_pkts[pktNum] = pkt;
	}
}

/**
*	@brief	������ݰ�����
*	@param	pkt	���ݰ�
*	@return	-
*/
void PacketPool::add(const Packet& pkt)
{
	if (!pkt.isEmpty())
		m_pkts[pkt.num] = pkt;
}

/**
*	@brief	�������ݰ���ţ��ӳ���ɾ��ָ�����ݰ�
*	@param	pktNum	���ݰ����
*	@return	-
*/
void PacketPool::remove(int pktNum)
{
	if (pktNum < 1 || pktNum > m_pkts.size())
		return;
	m_pkts.erase(pktNum);
}

void PacketPool::clear()
{
	if (m_pkts.size() > 0)
		m_pkts.clear();
}

/**
*	@brief	�������ݰ���ţ��ӳ��л�ȡָ�����ݰ�
*	@param	pktNum	���ݰ����
*	@return	pkt		���ݰ�����
*/
Packet& PacketPool::get(int pktNum)
{
	if (m_pkts.count(pktNum) > 0)
		return m_pkts[pktNum];
	return Packet();
}

/**
*	@brief	�ӳ��л�ȡ���һ�����ݰ�
*	@param	pktNum	���ݰ����
*	@return	pkt		���ݰ�����
*/
Packet& PacketPool::getLast()
{
	if (m_pkts.count(m_pkts.size()) > 0)
		return m_pkts[m_pkts.size()];
	return Packet();
}

/**
*	@brief	��ȡ���������ݰ�����
*	@param	-
*	@return	���ݰ�����
*/
int PacketPool::getSize() const
{
	return m_pkts.size();
}

/**
*	@brief	�жϳ����Ƿ�Ϊ��
*	@param	-
*	@return	true ��	false �ǿ�
*/
bool PacketPool::isEmpty() const
{
	if (m_pkts.size())
		return false;
	return true;
}


