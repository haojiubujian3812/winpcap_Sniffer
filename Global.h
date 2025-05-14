#define HAVE_REMOTE 
#include "pcap.h"
#include "remote-ext.h"
#include "Afxtempl.h"
#include "Packet.h"

#define PCAP_ERRBUFF_SIZE	50

/* ����ת�� ���涨��ʽ��name2ת��Ϊ����name1 */
void translateNameInDNS(char* name1, const char* name2);

/* DNS��Դ��¼���ݲ���ת�� ������ָ��c0�ĵ�ַdata2ת��Ϊ��ַdata1 offsetΪ��dns�ײ���ƫ����*/
void translateData(const DNS_Header* dnsh, char* data1, char* data2, const int data2_len);

/* �ж�data������ָ��0xc0,������ָ����data�е�λ��*/
int is0xC0PointerInName(char* name);

CString getNameInDNS(char* name, const DNS_Header* pDNSHeader);
CString get0xC0PointerValue(const DNS_Header* pDNSHeader, const int offset);
int is0xC0PointerInName(char* name);