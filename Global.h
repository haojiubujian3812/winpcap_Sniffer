#define HAVE_REMOTE 
#include "pcap.h"
#include "remote-ext.h"
#include "Afxtempl.h"
#include "Packet.h"

#define PCAP_ERRBUFF_SIZE	50

/* 域名转换 将规定格式的name2转换为域名name1 */
void translateNameInDNS(char* name1, const char* name2);

/* DNS资源记录数据部分转换 将带有指针c0的地址data2转换为地址data1 offset为到dns首部的偏移量*/
void translateData(const DNS_Header* dnsh, char* data1, char* data2, const int data2_len);

/* 判断data中有无指针0xc0,并返回指针在data中的位置*/
int is0xC0PointerInName(char* name);

CString getNameInDNS(char* name, const DNS_Header* pDNSHeader);
CString get0xC0PointerValue(const DNS_Header* pDNSHeader, const int offset);
int is0xC0PointerInName(char* name);