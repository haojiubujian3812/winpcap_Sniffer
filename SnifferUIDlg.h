
#include "afxwin.h"
#include "PacketDumper.h"
#include "PacketCatcher.h"
#include "PacketPool.h"
#include "ShortCutDialog.h"
#if !defined(AFX_SNIFFERUIDLG_H__22E6FA67_26EB_4787_8108_560D03B16680__INCLUDED_)
#define AFX_SNIFFERUIDLG_H__22E6FA67_26EB_4787_8108_560D03B16680__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
const int BITMAP_LIST_MAIN_SIZE = 5;
const int BITMAP_LIST_FILTER_SIZE = 3;
const int BITMAP_WIDTH = 24;
const int BITMAP_HEIGHT = 24;
class CSnifferUIDlg : public CDialog
{
	// Construction
public:
	CSnifferUIDlg(CWnd* pParent = NULL);	

	enum { IDD = IDD_SNIFFERUI_DIALOG };
protected:
	virtual void DoDataExchange(CDataExchange* pDX);	
protected:
	HICON		m_hIcon;
	HACCEL		m_hAccelMenu;
	HACCEL		m_hAccel;
	CMenu		m_menu;
	CToolBar	m_toolBarMain;
	CToolBar	m_toolBarFilter;
	CFont       m_comboFont;
	CComboBox	m_comboBoxDevList;
	CComboBox	m_comboBoxFilterList;
	CListCtrl	m_listCtrlPacketList;
	CTreeCtrl	m_treeCtrlPacketDetails;
	CEdit		m_editCtrlPacketBytes;
	CStatusBar  m_statusBar;

	/* 位图资源 */
	CBitmap		m_bitmapListMain[BITMAP_LIST_MAIN_SIZE];
	CBitmap		m_bitmapListFilter[BITMAP_LIST_FILTER_SIZE];
	CImageList	m_imageListMain;
	CImageList	m_imageListFilter;

	/* 标志 */
	bool    m_pktCaptureFlag;
	bool	m_fileOpenFlag;
	CString m_openFileName;	// 保存打开文件的文件名

	/* 数据包相关类 */
	PacketCatcher    m_catcher;  // 数据包捕获器
	PacketPool        m_pool;     // 数据包存储池

	/* 文件相关类 */
	PacketDumper	m_pktDumper;

	/* 初始化相关函数 */
	void initialAccelerator();
	void initialMenuBar();
    // Add the declaration of PreTranslateMessage in the CSnifferUIDlg class  
    public:  
	void initialToolBar();
	void initialComboBoxDevList();
	void initialComboBoxFilterList();
	void initialListCtrlPacketList();
	void initialTreeCtrlPacketDetails();
	void initialEditCtrlPacketBytes();
	void initialStatusBar();

	void updateStatusBar(const CString& status, int pktTotalNum, int pktDisplayNum);
	void OnSize(UINT nType, int cx, int cy);
	/* 文件夹操作相关函数 */
	bool createDirectory(const CString& dirPath);
	bool clearDirectory(const CString& dirPath);
	virtual BOOL PreTranslateMessage(MSG* pMsg) override;
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnClickedStart();
	afx_msg void OnClickedStop();
	afx_msg void OnClickedFilter();
    private:  
       pcap_if_t* m_pDevList; // 添加成员变量以定义 m_pDevList
	afx_msg void OnClickedClear();
	afx_msg void OnClickedList1(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnCustomdrawList1(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg LRESULT OnPktCatchMessage(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnTExitMessage(WPARAM wParam, LPARAM lParam);
	afx_msg BOOL OnToolTipText(UINT, NMHDR* pNMHDR, LRESULT* pResult);  // 工具条提示  
	afx_msg void OnKeydownList1(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnMenuFileOpen();
	afx_msg void OnMenuFileClose();
	afx_msg void OnMenuFileSaveAs();
	afx_msg void OnMenuFileClearCache();
	afx_msg void OnMenuFileExit();
	afx_msg void OnAcceleratorCtrlG();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
public:

	/* 控件打印相关函数 */
	int printListCtrlPacketList(const Packet& pkt);
	int printListCtrlPacketList(PacketPool& pool);
	int printListCtrlPacketList(PacketPool& pool, const CString& filter);

	int	printEditCtrlPacketBytes(const Packet& pkt);

	int printTreeCtrlPacketDetails(const Packet& pkt);
	int printEthernet2TreeCtrl(const Packet& pkt, HTREEITEM& parentNode);
	int	printIP2TreeCtrl(const Packet& pkt, HTREEITEM& parentNode);
	int	printARP2TreeCtrl(const Packet& pkt, HTREEITEM& parentNode);
	int	printICMP2TreeCtrl(const Packet& pkt, HTREEITEM& parentNode);
	int	printTCP2TreeCtrl(const Packet& pkt, HTREEITEM& parentNode);
	int	printUDP2TreeCtrl(const Packet& pkt, HTREEITEM& parentNode);
	int	printDNS2TreeCtrl(const Packet& pkt, HTREEITEM& parentNode);
	int	printDHCP2TreeCtrl(const Packet& pkt, HTREEITEM& parentNode);
	int	printHTTP2TreeCtrl(const Packet& pkt, HTREEITEM& parentNode);

	int printDNSHeader(const Packet& pkt, HTREEITEM& parentNode);
	HTREEITEM printDNSBanner(const Packet& pkt, HTREEITEM& parentNode);
	CString DNSType2CString(const u_short& type);
	CString DNSClass2CString(const u_short& classes);
	int printDNSQuery(char* DNSQuery, const u_short& questions, HTREEITEM& parentNode);
	int printDNSResourceRecord(char* DNSResourceRecord, const u_short& resourceRecordNum, const int& resourceRecordType, const DNS_Header* pDNSHeader, HTREEITEM parentNode);

	/* 转换 */
	CString	MACAddr2CString(const MAC_Address& addr);
	CString	IPAddr2CString(const IP_Address& addr);
	afx_msg void OnTvnSelchangedTree1(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnLvnItemchangedList1(NMHDR* pNMHDR, LRESULT* pResult);
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_SNIFFERUIDLG_H__22E6FA67_26EB_4787_8108_560D03B16680__INCLUDED_)
