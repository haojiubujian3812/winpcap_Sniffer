#include "stdafx.h"
#include "Packet.h"
#include "PacketCatcher.h"
#include "PacketDumper.h"
#include "PacketPool.h"
#include <pcap.h>
#include <WinSock2.h>
#include <string>
#include <iostream>
#include <time.h>

/**
 * @brief  数据包分析器类，整合了捕获、解析、管理和保存数据包的功能
 */
class PacketAnalyzer {
private:
    PacketPool* m_pool;           // 数据包池
    PacketCatcher* m_catcher;     // 数据包捕获器
    PacketDumper* m_dumper;       // 数据包保存器
    CString m_savePath;           // 保存路径
    bool m_isCapturing;           // 是否正在捕获
    
    // 协议类型统计
    int m_totalPackets;    // 总数据包数
    int m_arpPackets;      // ARP数据包数
    int m_ipPackets;       // IP数据包数
    int m_icmpPackets;     // ICMP数据包数
    int m_tcpPackets;      // TCP数据包数
    int m_udpPackets;      // UDP数据包数
    int m_dnsPackets;      // DNS数据包数
    int m_dhcpPackets;     // DHCP数据包数
    int m_httpPackets;     // HTTP数据包数
    
public:
    /**
     * @brief  构造函数，初始化各组件
     */
    PacketAnalyzer() {
        m_pool = new PacketPool();
        m_catcher = new PacketCatcher(m_pool);
        m_dumper = new PacketDumper();
        m_isCapturing = false;
        
        // 初始化统计数据
        m_totalPackets = 0;
        m_arpPackets = 0;
        m_ipPackets = 0;
        m_icmpPackets = 0;
        m_tcpPackets = 0;
        m_udpPackets = 0;
        m_dnsPackets = 0;
        m_dhcpPackets = 0;
        m_httpPackets = 0;
    }
    
    /**
     * @brief  析构函数，释放资源
     */
    ~PacketAnalyzer() {
        if (m_isCapturing) {
            stopCapture();
        }
        
        if (m_pool) {
            delete m_pool;
            m_pool = nullptr;
        }
        
        if (m_catcher) {
            delete m_catcher;
            m_catcher = nullptr;
        }
        
        if (m_dumper) {
            delete m_dumper;
            m_dumper = nullptr;
        }
    }
    
    /**
     * @brief  开始捕获数据包
     * @param  deviceIndex  网卡索引
     * @return 是否成功开始捕获
     */
    bool startCapture(int deviceIndex) {
        if (m_isCapturing) {
            return false; // 已经在捕获了
        }
        
        // 获取当前时间作为文件名
        CTime currentTime = CTime::GetCurrentTime();
        
        // 打开网卡
        if (!m_catcher->openAdapter(deviceIndex, currentTime)) {
            return false;
        }
        
        // 开始捕获
        m_catcher->startCapture(MODE_CAPTURE_LIVE);
        m_isCapturing = true;
        return true;
    }
    
    /**
     * @brief  停止捕获数据包
     */
    void stopCapture() {
        if (!m_isCapturing) {
            return;
        }
        
        m_catcher->stopCapture();
        m_catcher->closeAdapter();
        m_isCapturing = false;
    }
    
    /**
     * @brief  保存捕获的数据包到指定路径
     * @param  path  保存路径
     */
    void savePackets(CString path) {
        m_savePath = path;
        m_dumper->setPath(path);
        m_dumper->dump(path);
    }
    
    /**
     * @brief  分析所有已捕获的数据包
     */
    void analyzePackets() {
        if (m_pool->isEmpty()) {
            return;
        }
        
        // 重置统计数据
        m_totalPackets = m_pool->getSize();
        m_arpPackets = 0;
        m_ipPackets = 0;
        m_icmpPackets = 0;
        m_tcpPackets = 0;
        m_udpPackets = 0;
        m_dnsPackets = 0;
        m_dhcpPackets = 0;
        m_httpPackets = 0;
        
        // 遍历所有数据包进行分析
        for (int i = 1; i <= m_totalPackets; i++) {
            Packet& packet = m_pool->get(i);
            analyzePacket(packet);
        }
    }
    
    /**
     * @brief  分析单个数据包
     * @param  packet  数据包引用
     */
    void analyzePacket(Packet& packet) {
        if (packet.isEmpty()) {
            return;
        }
        
        // 以太网帧解析
        int ethResult = packet.decodeEthernet();
        
        // 根据以太网帧类型解析二层协议
        if (ethResult == 0x0800) { // IPv4
            m_ipPackets++;
            int ipResult = packet.decodeIP(packet.ethh->h_data);
            
            // 根据IP协议类型解析三层协议
            switch (ipResult) {
                case 1: // ICMP
                    m_icmpPackets++;
                    packet.decodeICMP(packet.iph->op_pad);
                    break;
                    
                case 6: // TCP
                    m_tcpPackets++;
                    int tcpResult = packet.decodeTCP(packet.iph->op_pad);
                    
                    // 检查端口，判断是否为HTTP或其他应用层协议
                    if (packet.tcph->src_port == 80 || packet.tcph->dst_port == 80 ||
                        packet.tcph->src_port == 8080 || packet.tcph->dst_port == 8080 ||
                        packet.tcph->src_port == 443 || packet.tcph->dst_port == 443) {
                        m_httpPackets++;
                        packet.decodeHTTP(packet.tcph->tcp_data);
                    }
                    break;
                    
                case 17: // UDP
                    m_udpPackets++;
                    int udpResult = packet.decodeUDP(packet.iph->op_pad);
                    
                    // 根据UDP端口判断上层协议
                    if (packet.udph->src_port == 53 || packet.udph->dst_port == 53) {
                        // DNS协议
                        m_dnsPackets++;
                        packet.decodeDNS(packet.udph->udp_data);
                    } else if ((packet.udph->src_port == 67 && packet.udph->dst_port == 68) ||
                              (packet.udph->src_port == 68 && packet.udph->dst_port == 67)) {
                        // DHCP协议
                        m_dhcpPackets++;
                        packet.decodeDHCP(packet.udph->udp_data);
                    }
                    break;
            }
        } else if (ethResult == 0x0806) { // ARP
            m_arpPackets++;
            packet.decodeARP(packet.ethh->h_data);
        }
    }
    
    /**
     * @brief  获取统计信息
     * @return 统计信息字符串
     */
    CString getStatistics() {
        CString stats;
        stats.Format(_T("总数据包数: %d\nARP数据包: %d\nIP数据包: %d\nICMP数据包: %d\nTCP数据包: %d\nUDP数据包: %d\nDNS数据包: %d\nDHCP数据包: %d\nHTTP数据包: %d"), 
                    m_totalPackets, m_arpPackets, m_ipPackets, m_icmpPackets, 
                    m_tcpPackets, m_udpPackets, m_dnsPackets, m_dhcpPackets, m_httpPackets);
        return stats;
    }
    
    /**
     * @brief  从文件中加载数据包
     * @param  filePath  文件路径
     * @return 是否成功加载
     */
    bool loadFromFile(CString filePath) {
        if (m_isCapturing) {
            stopCapture();
        }
        
        // 清空数据包池
        m_pool->clear();
        
        // 打开指定文件
        if (!m_catcher->openAdapter(filePath)) {
            return false;
        }
        
        // 开始从文件中捕获
        m_catcher->startCapture(MODE_CAPTURE_OFFLINE);
        
        return true;
    }
    
    /**
     * @brief  查找特定协议的数据包
     * @param  protocol  协议名称
     * @return 包含该协议的数据包数量
     */
    int findPacketsByProtocol(CString protocol) {
        int count = 0;
        
        for (int i = 1; i <= m_totalPackets; i++) {
            Packet& packet = m_pool->get(i);
            if (packet.protocol == protocol) {
                count++;
            }
        }
        
        return count;
    }
    
    /**
     * @brief  按照IP地址过滤数据包
     * @param  ipAddress  IP地址
     * @return 包含该IP的数据包数量
     */
    int filterPacketsByIP(CString ipAddress) {
        int count = 0;
        
        for (int i = 1; i <= m_totalPackets; i++) {
            Packet& packet = m_pool->get(i);
            
            // 如果是IP包，检查源地址和目标地址
            if (packet.iph) {
                CString srcIP, dstIP;
                srcIP.Format(_T("%d.%d.%d.%d"), 
                            packet.iph->src_ip.byte1, 
                            packet.iph->src_ip.byte2, 
                            packet.iph->src_ip.byte3, 
                            packet.iph->src_ip.byte4);
                
                dstIP.Format(_T("%d.%d.%d.%d"), 
                            packet.iph->dst_ip.byte1, 
                            packet.iph->dst_ip.byte2, 
                            packet.iph->dst_ip.byte3, 
                            packet.iph->dst_ip.byte4);
                
                if (srcIP == ipAddress || dstIP == ipAddress) {
                    count++;
                }
            }
        }
        
        return count;
    }
    
    /**
     * @brief  按照端口过滤数据包
     * @param  port  端口号
     * @return 包含该端口的数据包数量
     */
    int filterPacketsByPort(u_short port) {
        int count = 0;
        
        for (int i = 1; i <= m_totalPackets; i++) {
            Packet& packet = m_pool->get(i);
            
            // 检查TCP和UDP端口
            if (packet.tcph && (packet.tcph->src_port == port || packet.tcph->dst_port == port)) {
                count++;
            } else if (packet.udph && (packet.udph->src_port == port || packet.udph->dst_port == port)) {
                count++;
            }
        }
        
        return count;
    }
    
    /**
     * @brief  获取数据包池指针
     * @return 数据包池指针
     */
    PacketPool* getPacketPool() {
        return m_pool;
    }
    
    /**
     * @brief  获取数据包捕获器指针
     * @return 数据包捕获器指针
     */
    PacketCatcher* getPacketCatcher() {
        return m_catcher;
    }
    
    /**
     * @brief  获取数据包保存器指针
     * @return 数据包保存器指针
     */
    PacketDumper* getPacketDumper() {
        return m_dumper;
    }
};

/**
 * @brief  主函数，演示如何使用PacketAnalyzer类
 */
int main(int argc, char* argv[]) {
    // 初始化WinSock
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    // 创建数据包分析器
    PacketAnalyzer analyzer;
    
    // 列出所有网卡
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // 获取所有网卡
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return 1;
    }
    
    // 打印网卡列表
    int i = 0;
    for (pcap_if_t* d = alldevs; d; d = d->next) {
        std::cout << ++i << ". " << d->name << std::endl;
        if (d->description)
            std::cout << "   Description: " << d->description << std::endl;
    }
    
    if (i == 0) {
        std::cout << "\nNo interfaces found! Make sure WinPcap is installed.\n" << std::endl;
        return 1;
    }
    
    // 选择网卡
    int inum;
    std::cout << "\nEnter the interface number (1-" << i << "): ";
    std::cin >> inum;
    
    if (inum < 1 || inum > i) {
        std::cout << "Interface number out of range." << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }
    
    // 开始捕获
    std::cout << "Starting packet capture..." << std::endl;
    analyzer.getPacketCatcher()->setDevList(alldevs); // 设置网卡列表
    
    if (!analyzer.startCapture(inum - 1)) {
        std::cout << "Failed to start capturing." << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }
    
    // 捕获一段时间
    std::cout << "Capturing packets for 30 seconds..." << std::endl;
    Sleep(30000); // 30秒
    
    // 停止捕获
    analyzer.stopCapture();
    std::cout << "Capture stopped." << std::endl;
    
    // 分析数据包
    analyzer.analyzePackets();
    
    // 打印统计信息
    std::cout << std::endl << "Packet Analysis Results:" << std::endl;
    CString stats = analyzer.getStatistics();
    
    // 将CString转换为std::string以便于输出
    int bufferSize = WideCharToMultiByte(CP_ACP, 0, stats, -1, nullptr, 0, nullptr, nullptr);
    std::string statsStr(bufferSize - 1, '\0');
    WideCharToMultiByte(CP_ACP, 0, stats, -1, &statsStr[0], bufferSize, nullptr, nullptr);
    
    std::cout << statsStr << std::endl;
    
    // 保存数据包
    std::cout << "\nSaving packets to 'capture.pcap'..." << std::endl;
    analyzer.savePackets(_T("capture.pcap"));
    std::cout << "Packets saved." << std::endl;
    
    // 释放资源
    pcap_freealldevs(alldevs);
    WSACleanup();
    
    return 0;
}
