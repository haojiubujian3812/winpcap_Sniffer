#include "stdafx.h"
#include "SnifferUI.h"
#include "SnifferUIDlg.h"
#include "ThreadParam.h"
#include "Global.h"
#include "PacketCatcher.h"
#include <vector>
#define HAVE_REMOTE
#include "pcap.h"
#include <winver.h>
#include <stdexcept>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[_MAX_PATH] = __FILE__;
#endif
CTreeCtrl m_treeTrafficStats; // ȫ�ֱ�������

// ���캯������ʼ���Ի�����Դ���ؼ���Ա����
CSnifferUIDlg::CSnifferUIDlg(CWnd *pParent /*=NULL*/)
	: CDialog(CSnifferUIDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME); // ����������ͼ��
	m_catcher.setPool(&m_pool); // ��ʼ�����ݰ����������������ݰ���
	// m_dumper.setPool(&m_pool);		// ��ʼ�����ݰ�ת������ע��δ���ã�

	/* ״̬��־��ʼ�� */
	m_pktCaptureFlag = false; // ���ݰ�����״̬��־����ʼδ����
	m_fileOpenFlag = false;   // �ļ���״̬��־����ʼδ�򿪣�
}

// ���ݽ��������������Ի���ؼ����Ա����
void CSnifferUIDlg::DoDataExchange(CDataExchange *pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, m_listCtrlPacketList);   // �������ݰ��б�ؼ�
	DDX_Control(pDX, IDC_TREE1, m_treeCtrlPacketDetails); // �������ݰ��������οؼ�
	DDX_Control(pDX, IDC_EDIT1, m_editCtrlPacketBytes);   // �������ݰ��ֽ����༭�ؼ�
}

// ��Ϣӳ�������Ի�����Ϣ�봦�����Ĺ���
BEGIN_MESSAGE_MAP(CSnifferUIDlg, CDialog)
ON_WM_SYSCOMMAND()                  // ϵͳ������Ϣ����
ON_WM_PAINT()                       // ���ڻ�����Ϣ����
ON_WM_QUERYDRAGICON()               // �϶�ͼ���ѯ��Ϣ����
ON_NOTIFY(NM_CLICK, IDC_LIST1, OnClickedList1) // ���ݰ��б����¼�����

ON_NOTIFY(NM_CUSTOMDRAW, IDC_LIST1, &CSnifferUIDlg::OnCustomdrawList1) // �б��Զ�������¼�����
ON_MESSAGE(WM_PKTCATCH, &CSnifferUIDlg::OnPktCatchMessage) // �Զ������ݰ�������Ϣ����
ON_MESSAGE(WM_TEXIT, &CSnifferUIDlg::OnTExitMessage) // �Զ����߳��˳���Ϣ����
ON_NOTIFY(LVN_KEYDOWN, IDC_LIST1, &CSnifferUIDlg::OnKeydownList1) // �б����¼�����
ON_COMMAND(ID_MENU_FILE_OPEN, &CSnifferUIDlg::OnMenuFileOpen) // �˵����򿪡������
ON_COMMAND(ID_MENU_FILE_CLOSE, &CSnifferUIDlg::OnMenuFileClose) // �˵����رա������
ON_COMMAND(ID_MENU_FILE_CLEAR_CACHE, &CSnifferUIDlg::OnMenuFileClearCache) // �˵�����ջ��桱�����
ON_COMMAND(ID_MENU_FILE_SAVEAS, &CSnifferUIDlg::OnMenuFileSaveAs) // �˵������Ϊ�������
ON_COMMAND(ID_MENU_FILE_EXIT, &CSnifferUIDlg::OnMenuFileExit) // �˵�"�˳�"�����
ON_NOTIFY_EX(TTN_NEEDTEXT, 0, OnToolTipText) // ������ʾ�ı������¼�����
ON_COMMAND(ID_TOOLBARBTN_START, &CSnifferUIDlg::OnClickedStart) // ����������ʼ����ť�������
ON_COMMAND(ID_TOOLBARBTN_STOP, &CSnifferUIDlg::OnClickedStop) // ��������ֹͣ����ť�������
ON_COMMAND(ID_TOOLBARBTN_CLEAR, &CSnifferUIDlg::OnClickedClear) // ����������ա���ť�������
ON_COMMAND(ID_TOOLBARBTN_FILTER, &CSnifferUIDlg::OnClickedFilter) // �����������ˡ���ť�������
ON_NOTIFY(TVN_SELCHANGED, IDC_TREE1, OnTvnSelchangedTree1)
ON_WM_SIZE()
ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST1, &CSnifferUIDlg::OnLvnItemchangedList1)
END_MESSAGE_MAP()




BOOL CSnifferUIDlg::OnInitDialog()
{
	CDialog::OnInitDialog();
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu *pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		CString strAboutMenu;
		strAboutMenu.LoadString(IDS_ABOUTBOX);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}
	SetIcon(m_hIcon, TRUE);
	SetIcon(m_hIcon, FALSE); 
	initialAccelerator();						// ��ݼ���ʼ��
	initialMenuBar();								// �˵�����ʼ��
	initialToolBar();								// ��������ʼ��
	initialComboBoxDevList();				// �����б��ʼ��
	initialComboBoxFilterList();		// �������б��ʼ��
	initialListCtrlPacketList();		// �б�ؼ������ݰ��б���ʼ��
	initialTreeCtrlPacketDetails(); // ���οؼ������ݰ����飩��ʼ��
	initialEditCtrlPacketBytes();		// �༭�ؼ������ݰ��ֽ�������ʼ��
	initialStatusBar();							// ״̬����ʼ��
	createDirectory(".\\tmp");			// �ж�tmp�ļ����Ƿ���ڣ��������򴴽�
	return TRUE;										// return TRUE  unless you set the focus to a control
}
void CSnifferUIDlg::OnSize(UINT nType, int cx, int cy)
{
    CDialog::OnSize(nType, cx, cy);
    
    if (m_listCtrlPacketList.GetSafeHwnd() && m_treeCtrlPacketDetails.GetSafeHwnd() && m_editCtrlPacketBytes.GetSafeHwnd())
    {
        CRect rcClient;
        GetClientRect(&rcClient);
        rcClient.DeflateRect(5, 5);

        // ��ȡ�����������߶�
        int mainToolbarHeight = 0;
        int filterToolbarHeight = 0;
        if (m_toolBarMain.GetSafeHwnd()) {
            CRect rcMainToolBar;
            m_toolBarMain.GetWindowRect(&rcMainToolBar);
            mainToolbarHeight = rcMainToolBar.Height();
        }
        if (m_toolBarFilter.GetSafeHwnd()) {
            CRect rcFilterToolBar;
            m_toolBarFilter.GetWindowRect(&rcFilterToolBar);
            filterToolbarHeight = rcFilterToolBar.Height();
        }

        // �����ͻ�����ʼλ��
        rcClient.top += mainToolbarHeight + filterToolbarHeight + 10;

        // ����ؼ����򣨱���״̬���ռ䣩
        int statusBarHeight = 20;
        int listHeight = rcClient.Height() * 2 / 5;
        int remainingHeight = rcClient.Height() - listHeight - statusBarHeight - 15;

        // �������ؼ�����
        m_listCtrlPacketList.MoveWindow(rcClient.left, rcClient.top, rcClient.Width(), listHeight);
        m_treeCtrlPacketDetails.MoveWindow(rcClient.left, 
            rcClient.top + listHeight + 5, 
            rcClient.Width() / 2 - 3, 
            remainingHeight);
        m_editCtrlPacketBytes.MoveWindow(rcClient.left + rcClient.Width() / 2 + 3, 
            rcClient.top + listHeight + 5, 
            rcClient.Width() / 2 - 3, 
            remainingHeight);

        // ���¹�����λ��
        if (m_toolBarMain.GetSafeHwnd()) {
            m_toolBarMain.MoveWindow(5, 5, rcClient.Width() - 10, mainToolbarHeight);
        }
        if (m_toolBarFilter.GetSafeHwnd()) {
            m_toolBarFilter.MoveWindow(5, 5 + mainToolbarHeight + 5, rcClient.Width() - 10, filterToolbarHeight);
        }

        // ����״̬��λ��
        if (m_statusBar.GetSafeHwnd()) {
            CRect rcStatus;
            m_statusBar.GetWindowRect(&rcStatus);
            m_statusBar.MoveWindow(0, rcClient.top + listHeight + remainingHeight + 20, 
                rcClient.Width(), statusBarHeight);
            m_statusBar.Invalidate();
        }
    }
}
void CSnifferUIDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, (WPARAM)dc.GetSafeHdc(), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

HCURSOR CSnifferUIDlg::OnQueryDragIcon()
{

	return (HCURSOR)m_hIcon;
}
void CSnifferUIDlg::OnClickedStart()
{
	// ��ȡ��ǰʱ��
	time_t tt = time(NULL);
	struct tm tm_now;
	localtime_s(&tm_now, &tt);
	CTime currentTime(tm_now.tm_year + 1900, tm_now.tm_mon + 1, tm_now.tm_mday,
										tm_now.tm_hour, tm_now.tm_min, tm_now.tm_sec);

	/* ��û��ѡ������������ʾ��Ϣ�����򣬴����߳�ץ�� */
	int selItemIndex = m_comboBoxDevList.GetCurSel();
	if (selItemIndex <= 0)
	{
		AfxMessageBox(_T("��ѡ������"), MB_OK);
		return;
	}

	if (m_catcher.openAdapter(selItemIndex, currentTime))
	{
		CString status = "���ڲ���" + m_catcher.getDevName();
		/* �޸Ŀؼ�ʹ��״̬ */
		m_comboBoxDevList.EnableWindow(FALSE);
		m_toolBarMain.GetToolBarCtrl().EnableButton(ID_TOOLBARBTN_START, FALSE);
		m_toolBarMain.GetToolBarCtrl().EnableButton(ID_TOOLBARBTN_STOP, TRUE);

		m_toolBarMain.GetToolBarCtrl().EnableButton(ID_MENU_FILE_OPEN, FALSE);
		m_toolBarMain.GetToolBarCtrl().EnableButton(ID_MENU_FILE_SAVEAS, FALSE);

		m_menu.EnableMenuItem(ID_MENU_FILE_OPEN, MF_GRAYED);	// ���ò˵���"��"
		m_menu.EnableMenuItem(ID_MENU_FILE_CLOSE, MF_GRAYED); // ���ò˵���"�ر�"
		m_menu.EnableMenuItem(ID_MENU_FILE_OPEN, MF_GRAYED);	// ���ò˵���"���Ϊ"

		/* ��տؼ���ʾ���� */
		m_listCtrlPacketList.DeleteAllItems();
		m_treeCtrlPacketDetails.DeleteAllItems();
		m_editCtrlPacketBytes.SetWindowText(_T(""));

		AfxGetMainWnd()->SetWindowText(status);

		/* ����ڴ������ݰ��� */
		m_pool.clear();

		/* ����״̬�� */
		updateStatusBar(status, m_pool.getSize(), m_listCtrlPacketList.GetItemCount());

		CString fileName = "winpcap_sniffer_" + currentTime.Format("%Y%m%d%H%M%S") + ".pcap";
		m_pktDumper.setPath(".\\tmp\\" + fileName);

		m_catcher.startCapture(MODE_CAPTURE_LIVE);
		m_pktCaptureFlag = true;

		m_openFileName = fileName;
		m_fileOpenFlag = true;
	}
}

void CSnifferUIDlg::OnClickedStop()
{
	CString status = "���������" + m_catcher.getDevName();
	AfxGetMainWnd()->SetWindowText(m_pktDumper.getPath()); // �޸ı�����

	m_comboBoxDevList.EnableWindow(TRUE);
	m_toolBarMain.GetToolBarCtrl().EnableButton(ID_TOOLBARBTN_START, TRUE);
	m_toolBarMain.GetToolBarCtrl().EnableButton(ID_TOOLBARBTN_STOP, FALSE);
	m_toolBarMain.GetToolBarCtrl().EnableButton(ID_MENU_FILE_OPEN, TRUE);
	m_toolBarMain.GetToolBarCtrl().EnableButton(ID_MENU_FILE_SAVEAS, TRUE);

	m_menu.EnableMenuItem(ID_MENU_FILE_OPEN, MF_ENABLED);		// ���ò˵���"��"
	m_menu.EnableMenuItem(ID_MENU_FILE_CLOSE, MF_GRAYED);		// ���ò˵���"�ر�"
	m_menu.EnableMenuItem(ID_MENU_FILE_SAVEAS, MF_ENABLED); // ���ò˵���"���Ϊ"
	m_statusBar.SetPaneText(0, status, true);								// �޸�״̬

	m_catcher.stopCapture();
	m_pktCaptureFlag = false;
	// m_catcher.closeAdapter();
}
void CSnifferUIDlg::OnClickedFilter()
{
	int selIndex = m_comboBoxFilterList.GetCurSel();
	if (selIndex <= 0)
		return;
	CString strFilter;
	m_comboBoxFilterList.GetLBText(selIndex, strFilter);

	m_listCtrlPacketList.DeleteAllItems();
	m_treeCtrlPacketDetails.DeleteAllItems();
	m_editCtrlPacketBytes.SetWindowText(_T(""));

	printListCtrlPacketList(m_pool, strFilter);
	updateStatusBar(CString(""), m_pool.getSize(), m_listCtrlPacketList.GetItemCount());
}

void CSnifferUIDlg::OnClickedClear()
{
	m_comboBoxFilterList.SetCurSel(0);
	m_listCtrlPacketList.DeleteAllItems();
	m_treeCtrlPacketDetails.DeleteAllItems();
	m_editCtrlPacketBytes.SetWindowText(_T(""));

	printListCtrlPacketList(m_pool);
	updateStatusBar(CString(""), m_pool.getSize(), m_listCtrlPacketList.GetItemCount());
}

void CSnifferUIDlg::initialAccelerator()
{
    m_hAccelMenu = ::LoadAccelerators(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDR_MENU1));
    m_hAccel = ::LoadAccelerators(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDR_ACCELERATOR));
}

void CSnifferUIDlg::initialMenuBar()
{
	m_menu.LoadMenu(IDR_MENU1);
	SetMenu(&m_menu);

	/* �˵������ */
	//	CMenu* pMenu = this->GetMenu();
	if (m_menu)
	{
		m_menu.EnableMenuItem(ID_MENU_FILE_CLOSE, MF_GRAYED);	 // ���ò˵���"�ر�"
		m_menu.EnableMenuItem(ID_MENU_FILE_SAVEAS, MF_GRAYED); // ���ò˵���"���Ϊ"
	}
}

void CSnifferUIDlg::initialToolBar()
{
	// ������������
	if (!m_toolBarMain.CreateEx(this, TBSTYLE_FLAT, WS_CHILD | WS_VISIBLE | CBRS_TOP | CBRS_TOOLTIPS | CBRS_GRIPPER | CBRS_FLYBY | CBRS_SIZE_DYNAMIC) ||
			!m_toolBarMain.LoadToolBar(IDR_TOOLBAR1))
	{
		AfxMessageBox(_T("δ�ܴ�����������\n"));
		return;
	}

	int index = m_toolBarMain.CommandToIndex(ID_TOOLBARBTN_DEVLIST);
	m_toolBarMain.SetButtonInfo(index, ID_TOOLBARBTN_DEVLIST, TBBS_SEPARATOR, 300); 
	CRect rect;
	m_toolBarMain.GetItemRect(index, &rect);
	rect.top += 3;
	rect.bottom += 200;
	rect.left += 10;
	m_comboBoxDevList.Create(WS_CHILD | WS_VISIBLE | WS_VSCROLL | CBS_DROPDOWNLIST, rect, &m_toolBarMain, ID_TOOLBARBTN_DEVLIST);

	// ��ȡ����������ťͼ�꣬�洢��ImageList����������ȡImageList
	m_imageListMain.Create(BITMAP_WIDTH, BITMAP_HEIGHT, ILC_COLOR24 | ILC_MASK, 0, 0);
	for (int i = 0; i < BITMAP_LIST_MAIN_SIZE; ++i)
	{
		m_bitmapListMain[i].LoadBitmapA(IDB_BITMAP_DEV + i);
		m_imageListMain.Add(&m_bitmapListMain[i], RGB(0, 0, 0));
	}
	m_toolBarMain.GetToolBarCtrl().SetImageList(&m_imageListMain);

	// �������������ϵİ�ť
	m_toolBarMain.GetToolBarCtrl().EnableButton(ID_TOOLBARBTN_STOP, FALSE);
	m_toolBarMain.GetToolBarCtrl().EnableButton(ID_MENU_FILE_SAVEAS, FALSE);

	// ����������������
	if (!m_toolBarFilter.CreateEx(this, TBSTYLE_FLAT, WS_CHILD | WS_VISIBLE | CBRS_TOP | CBRS_TOOLTIPS | CBRS_GRIPPER | CBRS_FLYBY | CBRS_SIZE_DYNAMIC) ||
			!m_toolBarFilter.LoadToolBar(IDR_TOOLBAR2))
	{
		AfxMessageBox(_T("δ�ܴ���������������\n"));
		return;
	}

	// �ڹ�������������ť�ϴ�����Ͽ򣨹������б�
	index = m_toolBarFilter.CommandToIndex(ID_TOOLBARBTN_FILTERLIST);
	m_toolBarFilter.SetButtonInfo(index, ID_TOOLBARBTN_FILTERLIST, TBBS_SEPARATOR, 300); // ������Ͽ��ID�����ͣ������Ƿָ�������300��ָ�ָ������

	// ���ݷָ����ĳߴ�rect������Ͽ�
	m_toolBarFilter.GetItemRect(index, &rect);
	rect.top += 3;
	rect.bottom += 200;  // ������������߶�
	rect.left += 10;
	m_comboBoxFilterList.Create(WS_CHILD | WS_VISIBLE | WS_VSCROLL | CBS_DROPDOWNLIST, rect, &m_toolBarFilter, ID_TOOLBARBTN_FILTERLIST);

	// ��ȡ��������������ťͼ�꣬�洢��ImageList����������ȡImageList
	m_imageListFilter.Create(BITMAP_WIDTH, BITMAP_HEIGHT, ILC_COLOR24 | ILC_MASK, 0, 0);
	for (int i = 0; i < BITMAP_LIST_FILTER_SIZE; ++i)
	{
		m_bitmapListFilter[i].LoadBitmapA(IDB_BITMAP_DEV + BITMAP_LIST_MAIN_SIZE + i);
		m_imageListFilter.Add(&m_bitmapListFilter[i], RGB(0, 0, 0));
	}
	m_toolBarFilter.GetToolBarCtrl().SetImageList(&m_imageListFilter);

	// ���������б�����
	m_comboFont.CreateFontA(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, 0, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_ROMAN, "������");
	m_comboBoxDevList.SetFont(&m_comboFont);
	m_comboBoxFilterList.SetFont(&m_comboFont);

	// ���������б�߶�
	m_comboBoxDevList.SetItemHeight(-1, 18);
	m_comboBoxFilterList.SetItemHeight(-1, 18);

	// �ؼ�����λ
	RepositionBars(AFX_IDW_CONTROLBAR_FIRST, AFX_IDW_CONTROLBAR_LAST, 0);
}
void CSnifferUIDlg::initialComboBoxDevList()
{
	m_comboBoxDevList.AddString("ѡ������");
	m_comboBoxDevList.SetCurSel(0);

	pcap_if_t* dev = NULL;
	pcap_if_t* allDevs = NULL;
	char errbuf[PCAP_ERRBUF_SIZE + 1];
	if (pcap_findalldevs(&allDevs, errbuf) == -1)
	{
		AfxMessageBox(_T("pcap_findalldevs����!"), MB_OK);
		return;
	}
	for (dev = allDevs; dev != NULL; dev = dev->next)
	{
		if (dev->description != NULL)
			m_comboBoxDevList.AddString(dev->description);
	}
	m_catcher.setDevList(allDevs);
	//pcap_freealldevs(allDevs);
}

void CSnifferUIDlg::initialComboBoxFilterList()
{
	std::vector<CString> filterList;
	filterList.push_back("Ethernet");
	filterList.push_back("IP");
	filterList.push_back("ARP");
	filterList.push_back("ICMP");
	filterList.push_back("TCP");
	filterList.push_back("UDP");
	filterList.push_back("DNS");
	filterList.push_back("DHCP");
	filterList.push_back("HTTP");

	m_comboBoxFilterList.AddString("ѡ�����������ѡ��");
	m_comboBoxFilterList.SetCurSel(0);

	for (const auto& filter : filterList) {
		m_comboBoxFilterList.AddString(filter);
		//AfxMessageBox(filter);
	}
        

}
void CSnifferUIDlg::initialListCtrlPacketList()
{
	CRect rect;
	m_toolBarFilter.GetWindowRect(&rect);
	ScreenToClient(&rect);
	GetDlgItem(IDC_LIST1)->SetWindowPos(NULL, rect.left, rect.bottom + 5, 0, 0, SWP_NOZORDER | SWP_NOSIZE);

	DWORD dwStyle = m_listCtrlPacketList.GetExtendedStyle(); // ����б�ؼ���������
	dwStyle |= LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_HEADERDRAGDROP;
	m_listCtrlPacketList.SetExtendedStyle(dwStyle);

	m_listCtrlPacketList.GetWindowRect(&rect);
	ScreenToClient(&rect);

	int index = 0;
	m_listCtrlPacketList.InsertColumn(index, "���", LVCFMT_CENTER, rect.Width() * 0.05);
	m_listCtrlPacketList.InsertColumn(++index, "ʱ��", LVCFMT_CENTER, rect.Width() * 0.15);
	m_listCtrlPacketList.InsertColumn(++index, "Э��", LVCFMT_CENTER, rect.Width() * 0.05);
	m_listCtrlPacketList.InsertColumn(++index, "����", LVCFMT_CENTER, rect.Width() * 0.05);
	m_listCtrlPacketList.InsertColumn(++index, "ԴMAC��ַ", LVCFMT_CENTER, rect.Width() * 0.175);
	m_listCtrlPacketList.InsertColumn(++index, "Ŀ��MAC��ַ", LVCFMT_CENTER, rect.Width() * 0.175);
	m_listCtrlPacketList.InsertColumn(++index, "ԴIP��ַ", LVCFMT_CENTER, rect.Width() * 0.175);
	m_listCtrlPacketList.InsertColumn(++index, "Ŀ��IP��ַ", LVCFMT_CENTER, rect.Width() * 0.175);

}

void CSnifferUIDlg::initialTreeCtrlPacketDetails()
{
	// �����б�ؼ������ݰ��б�λ�õ������οؼ������ݰ����飩λ��
	CRect rect, winRect;
	m_listCtrlPacketList.GetWindowRect(&rect);
	ScreenToClient(&rect);
	GetDlgItem(IDC_TREE1)->SetWindowPos(NULL, rect.left, rect.bottom + 5, rect.Width() * 0.5, rect.Height() + 125, SWP_NOZORDER);
}

void CSnifferUIDlg::initialEditCtrlPacketBytes()
{
	// �������οؼ��ؼ������ݰ����飩λ�õ����༭�ؼ������ݰ��ֽ�����λ��
	CRect rect;
	m_treeCtrlPacketDetails.GetWindowRect(&rect);
	ScreenToClient(&rect);
	GetDlgItem(IDC_EDIT1)->SetWindowPos(NULL, rect.right + 5, rect.top, rect.Width(), rect.Height(), SWP_NOZORDER);
}

void CSnifferUIDlg::initialStatusBar()
{
	if (m_statusBar.Create(this)) // �����˵���
	{
		static UINT indicators[] =
				{
						ID_INDICATOR_STATUS,
						ID_INDICATOR_PKT_TOTAL_NUM,
						ID_INDICATOR_PKT_DISPLAY_NUM};
		int indicatorsSize = sizeof(indicators) / sizeof(UINT);
		m_statusBar.SetIndicators(indicators, indicatorsSize);
		CRect rect;
		GetClientRect(rect);
		int index = 0;
		m_statusBar.SetPaneInfo(index, ID_INDICATOR_STATUS, SBPS_STRETCH, rect.Width() * 0.6);
		m_statusBar.SetPaneInfo(++index, ID_INDICATOR_PKT_TOTAL_NUM, SBPS_NORMAL, rect.Width() * 0.2);
		m_statusBar.SetPaneInfo(++index, ID_INDICATOR_PKT_DISPLAY_NUM, SBPS_NORMAL, rect.Width() * 0.15);
		RepositionBars(AFX_IDW_CONTROLBAR_FIRST, AFX_IDW_CONTROLBAR_LAST, 0); // ��ʾ״̬��
	}
}
/**
 *	@brief	����״̬��
 *	@param [in]	status	״̬
 *	@param [in]	pktTotalNum	���ݰ�����	ֵΪ�Ǹ���ʱ���¸��ֶ�
 *	@param [in]	pktDisplayNum	���ݰ���ʾ����	ֵΪ�Ǹ���ʱ���¸��ֶ�
 *	@return	-
 */
void CSnifferUIDlg::updateStatusBar(const CString &status, int pktTotalNum, int pktDisplayNum)
{
	if (!status.IsEmpty())
	{
		int index = m_statusBar.CommandToIndex(ID_INDICATOR_STATUS);
		m_statusBar.SetPaneText(index, status, TRUE);
	}
	if (pktTotalNum >= 0)
	{
		int index = m_statusBar.CommandToIndex(ID_INDICATOR_PKT_TOTAL_NUM);
		CString text;
		text.Format("���ݰ���%d", pktTotalNum);
		m_statusBar.SetPaneText(index, text, TRUE);
	}
	if (pktDisplayNum >= 0)
	{
		int index = m_statusBar.CommandToIndex(ID_INDICATOR_PKT_DISPLAY_NUM);
		CString text;
		double percentage = (pktDisplayNum == 0 || pktTotalNum == 0) ? 0.0 : ((double)pktDisplayNum / pktTotalNum * 100);
		text.Format("����ʾ��%d (%.1f%%)", pktDisplayNum, percentage);
		m_statusBar.SetPaneText(index, text, TRUE);
	}
}

/**
 *	@brief	��ָ��·���ϴ����ļ���
 *	@param [in]	dirPath	 �ļ���·��
 *	@return	true �����ɹ� false ����ʧ�ܣ��ļ����Ѵ��ڣ�
 */
bool CSnifferUIDlg::createDirectory(const CString &dirPath)
{
	if (!PathIsDirectory(dirPath.GetString())) // �Ƿ��������ļ���
	{
		::CreateDirectory(dirPath.GetString(), 0);
		return true;
	}
	return false;
}

/**
 *	@brief	���ָ���ļ����������ļ�
 *	@param [in]	dirPath	 �ļ���·��
 *	@return	true ��ճɹ� false ���ʧ��
 */
bool CSnifferUIDlg::clearDirectory(const CString &dirPath)
{
	CFileFind finder;
	CString path(dirPath);
	path += _T("\\*.*");

	BOOL isFound = finder.FindFile(path);
	if (!isFound)
	{
		return false;
	}
	while (isFound)
	{
		isFound = finder.FindNextFile();

		// ���� . �� .. ; �������������ѭ����
		if (finder.IsDots())
			continue;

		// �����Ŀ¼���������� ���ݹ飩
		if (finder.IsDirectory())
		{
			CString subDirPath = dirPath + finder.GetFileName();
			clearDirectory(subDirPath);	 // ɾ���ļ����µ��ļ�
			RemoveDirectory(subDirPath); // �Ƴ����ļ�
		}
		else
		{
			CString filePath = dirPath + finder.GetFileName();
			DeleteFile(filePath);
		}
	}
	finder.Close();
	return true;
}

/**
 *	@brief	��ӡ���ݰ���Ҫ��Ϣ���б�ؼ�
 *	@param	���ݰ�
 *	@return	0 ��ӡ�ɹ�	-1 ��ӡʧ��
 */
int CSnifferUIDlg::printListCtrlPacketList(const Packet &pkt)
{
	if (pkt.isEmpty())
		return -1;

	int row = 0; // �к�
	int col = 0; // �к�
	/* ��ӡ��� */
	CString strNum;
	strNum.Format("%d", pkt.num);

	UINT mask = LVIF_PARAM | LVIF_TEXT;

	// protocol�ֶ���OnCustomdrawList1()��ʹ��
	row = m_listCtrlPacketList.InsertItem(mask, m_listCtrlPacketList.GetItemCount(), strNum, 0, 0, 0, (LPARAM) & (pkt.protocol));

	/* ��ӡʱ�� */
	CTime pktArrivalTime((time_t)(pkt.header->ts.tv_sec));
	CString strPktArrivalTime = pktArrivalTime.Format("%Y/%m/%d %H:%M:%S");
	m_listCtrlPacketList.SetItemText(row, ++col, strPktArrivalTime);

	/* ��ӡЭ�� */
	if (!pkt.protocol.IsEmpty())
		m_listCtrlPacketList.SetItemText(row, ++col, pkt.protocol);
	else
		++col;

	/* ��ӡ���� */
	CString strCaplen;
	strCaplen.Format("%d", pkt.header->caplen);
	m_listCtrlPacketList.SetItemText(row, ++col, strCaplen);

	/* ��ӡԴĿMAC��ַ */
	if (pkt.ethh != NULL)
	{
		CString strSrcMAC = MACAddr2CString(pkt.ethh->srcaddr);
		CString strDstMAC = MACAddr2CString(pkt.ethh->dstaddr);

		m_listCtrlPacketList.SetItemText(row, ++col, strSrcMAC);
		m_listCtrlPacketList.SetItemText(row, ++col, strDstMAC);
	}
	else
	{
		col += 2;
	}

	/* ��ӡԴĿIP��ַ */
	if (pkt.iph != NULL)
	{
		CString strSrcIP = IPAddr2CString(pkt.iph->srcaddr);
		CString strDstIP = IPAddr2CString(pkt.iph->dstaddr);

		m_listCtrlPacketList.SetItemText(row, ++col, strSrcIP);
		m_listCtrlPacketList.SetItemText(row, ++col, strDstIP);
	}
	else
	{
		col += 2;
	}
	return 0;
}

/**
 *	@brief	��ӡ���ݰ���Ҫ��Ϣ���б�ؼ�
 *	@param	pool ���ݰ���
 *	@return	>=0 ���ݰ��������ݰ����� -1 ��ӡʧ��
 */
int CSnifferUIDlg::printListCtrlPacketList(PacketPool &pool)
{
	if (pool.isEmpty())
		return -1;
	int pktNum = pool.getSize();
	for (int i = 1; i <= pktNum; ++i)
		printListCtrlPacketList(pool.get(i));

	return pktNum;
}

/**
 *	@brief	�������ݰ��������ݹ��������ƴ�ӡ���ݰ����б�ؼ�
 *	@param	packetLinkList	���ݰ�����
 *	@param	filter	����������
 *	@return	>=0 ���˳������ݰ�����	-1 ��ӡʧ��
 */
int CSnifferUIDlg::printListCtrlPacketList(PacketPool &pool, const CString &filter)
{
	if (pool.isEmpty() || filter.IsEmpty())
		return -1;

	int pktNum = pool.getSize();
	int filterPktNum = 0;
	for (int i = 0; i < pktNum; ++i)
	{
		const Packet &pkt = pool.get(i); // BUG��������
		if (pkt.protocol == filter)
		{
			printListCtrlPacketList(pkt);
			++filterPktNum;
		}
	}
	return filterPktNum;
}
int CSnifferUIDlg::printEditCtrlPacketBytes(const Packet &pkt)
{
	if (pkt.isEmpty())
	{
		return -1;
	}

	CString strPacketBytes, strTmp;
	u_char *pHexPacketBytes = pkt.pkt_data;
	u_char *pASCIIPacketBytes = pkt.pkt_data;
	for (int byteCount = 0, byteCount16 = 0, offset = 0; byteCount < pkt.header->caplen && pHexPacketBytes != NULL; ++byteCount)
	{
		/* ����ǰ�ֽ������ף���ӡ����ƫ���� */
		if (byteCount % 16 == 0)
		{
			strTmp.Format("%04X:", offset);
			strPacketBytes += strTmp + " ";
		}

		/* ��ӡ16�����ֽ� */
		strTmp.Format("%02X", *pHexPacketBytes);
		strPacketBytes += strTmp + " ";
		++pHexPacketBytes;
		++byteCount16;

		switch (byteCount16)
		{
		case 8:
		{
			/* ÿ��ȡ8���ֽڴ�ӡһ���Ʊ�� */
			strPacketBytes += "\t";
			// strPacketBytes += "#";
		}
		break;
		case 16:
		{
			/* ÿ��ȡ16���ֽڴ�ӡ��Ӧ�ֽڵ�ASCII�ַ���ֻ��ӡ��ĸ���� */
			if (byteCount16 == 16)
			{
				strPacketBytes += " ";
				for (int charCount = 0; charCount < 16; ++charCount, ++pASCIIPacketBytes)
				{
					strTmp.Format("%c", isalnum(*pASCIIPacketBytes) ? *pASCIIPacketBytes : '.');
					strPacketBytes += strTmp;
				}
				strPacketBytes += "\r\n";
				offset += 16;
				byteCount16 = 0;
			}
		}
		break;
		default:
			break;
		}
	}
	/* �����ݰ��ܳ��Ȳ���16�ֽڶ���ʱ����ӡ���һ���ֽڶ�Ӧ��ASCII�ַ� */
	if (pkt.header->caplen % 16 != 0)
	{
		/* �ո���䣬��֤�ֽ���16�ֽڶ��� */
		for (int spaceCount = 0, byteCount16 = (pkt.header->caplen % 16); spaceCount < 16 - (pkt.header->caplen % 16); ++spaceCount)
		{
			strPacketBytes += "  ";
			strPacketBytes += " ";
			++byteCount16;
			if (byteCount16 == 8)
			{
				strPacketBytes += "\t";
				// strPacketBytes += "#";
			}
		}
		strPacketBytes += " ";
		/* ��ӡ���һ���ֽڶ�Ӧ��ASCII�ַ� */
		for (int charCount = 0; charCount < (pkt.header->caplen % 16); ++charCount, ++pASCIIPacketBytes)
		{
			strTmp.Format("%c", isalnum(*pASCIIPacketBytes) ? *pASCIIPacketBytes : '.');
			strPacketBytes += strTmp;
		}
		strPacketBytes += "\r\n";
	}

	m_editCtrlPacketBytes.SetWindowTextA(strPacketBytes);

	return 0;
}
int CSnifferUIDlg::printTreeCtrlPacketDetails(const Packet &pkt)
{
	if (pkt.isEmpty())
		return -1;

	m_treeCtrlPacketDetails.DeleteAllItems();

	/* ������Ž�� */
	CString strText;

	CTime pktArrivalTime((time_t)(pkt.header->ts.tv_sec));
	CString strPktArrivalTime = pktArrivalTime.Format("%Y/%m/%d %H:%M:%S");

	strText.Format("��%d�����ݰ���%s, �� %hu �ֽ�, ���� %hu �ֽڣ�", pkt.num, strPktArrivalTime, pkt.header->len, pkt.header->caplen);

	HTREEITEM rootNode = m_treeCtrlPacketDetails.InsertItem(strText, TVI_ROOT);
	if (pkt.ethh != NULL)
	{
		printEthernet2TreeCtrl(pkt, rootNode);
	}

	m_treeCtrlPacketDetails.Expand(rootNode, TVE_EXPAND);
	return 0;
}
int CSnifferUIDlg::printEthernet2TreeCtrl(const Packet &pkt, HTREEITEM &parentNode)
{
	if (pkt.isEmpty() || pkt.ethh == NULL || parentNode == NULL)
	{
		return -1;
	}
	/* ��ȡԴĿMAC��ַ */
	CString strSrcMAC = MACAddr2CString(pkt.ethh->srcaddr);
	CString strDstMAC = MACAddr2CString(pkt.ethh->dstaddr);
	CString strEthType;
	strEthType.Format("0x%04X", ntohs(pkt.ethh->eth_type));

	HTREEITEM EthNode = m_treeCtrlPacketDetails.InsertItem("��̫����" + strSrcMAC + " -> " + strDstMAC + "��", parentNode, 0);

	m_treeCtrlPacketDetails.InsertItem("Ŀ��MAC��ַ��" + strDstMAC, EthNode, 0);
	m_treeCtrlPacketDetails.InsertItem("ԴMAC��ַ��" + strSrcMAC, EthNode, 0);
	m_treeCtrlPacketDetails.InsertItem("���ͣ�" + strEthType, EthNode, 0);

	if (pkt.iph != NULL)
	{
		printIP2TreeCtrl(pkt, parentNode);
	}
	else if (pkt.arph != NULL)
	{
		printARP2TreeCtrl(pkt, parentNode);
	}
	return 0;
}
int CSnifferUIDlg::printIP2TreeCtrl(const Packet &pkt, HTREEITEM &parentNode)
{
	if (pkt.isEmpty() || pkt.iph == NULL || parentNode == NULL)
		return -1;

	HTREEITEM IPNode = m_treeCtrlPacketDetails.InsertItem("IP��" + IPAddr2CString(pkt.iph->srcaddr) + " -> " + IPAddr2CString(pkt.iph->dstaddr) + "��", parentNode, 0);
	CString strText;

	strText.Format("�汾�ţ�%d", pkt.iph->ver_headerlen >> 4);
	m_treeCtrlPacketDetails.InsertItem(strText, IPNode, 0);

	strText.Format("�ײ����ȣ�%d �ֽڣ�%d��", pkt.getIPHeaderLegnth(), pkt.getIPHeaderLengthRaw());
	m_treeCtrlPacketDetails.InsertItem(strText, IPNode, 0);

	strText.Format("����������0x%02X", pkt.iph->tos);
	m_treeCtrlPacketDetails.InsertItem(strText, IPNode, 0);

	strText.Format("�ܳ��ȣ�%hu", ntohs(pkt.iph->totallen));
	m_treeCtrlPacketDetails.InsertItem(strText, IPNode, 0);

	strText.Format("��ʶ��0x%04hX��%hu��", ntohs(pkt.iph->identifier), ntohs(pkt.iph->identifier));
	m_treeCtrlPacketDetails.InsertItem(strText, IPNode, 0);

	strText.Format("��־��0x%02X", pkt.getIPFlags());
	HTREEITEM IPFlagNode = m_treeCtrlPacketDetails.InsertItem(strText, IPNode, 0);

	strText = "RSV��0";
	m_treeCtrlPacketDetails.InsertItem(strText, IPFlagNode, 0);

	strText.Format("DF��%d", pkt.getIPFlagDF());
	m_treeCtrlPacketDetails.InsertItem(strText, IPFlagNode, 0);

	strText.Format("MF��%d", pkt.getIPFlagsMF());
	m_treeCtrlPacketDetails.InsertItem(strText, IPFlagNode, 0);

	strText.Format("Ƭƫ�ƣ�%d", pkt.getIPOffset());
	m_treeCtrlPacketDetails.InsertItem(strText, IPNode, 0);

	strText.Format("TTL��%u", pkt.iph->ttl);
	m_treeCtrlPacketDetails.InsertItem(strText, IPNode, 0);

	switch (pkt.iph->protocol)
	{
	case PROTOCOL_ICMP:
		strText = "Э�飺ICMP��1��";
		break;
	case PROTOCOL_TCP:
		strText = "Э�飺TCP��6��";
		break;
	case PROTOCOL_UDP:
		strText = "Э�飺UDP��17��";
		break;
	default:
		strText.Format("Э�飺δ֪��%d��", pkt.iph->protocol);
		break;
	}
	m_treeCtrlPacketDetails.InsertItem(strText, IPNode, 0);

	strText.Format("У��ͣ�0x%02hX", ntohs(pkt.iph->checksum));
	m_treeCtrlPacketDetails.InsertItem(strText, IPNode, 0);

	strText = "ԴIP��ַ��" + IPAddr2CString(pkt.iph->srcaddr);
	m_treeCtrlPacketDetails.InsertItem(strText, IPNode, 0);

	strText = "Ŀ��IP��ַ��" + IPAddr2CString(pkt.iph->dstaddr);
	m_treeCtrlPacketDetails.InsertItem(strText, IPNode, 0);

	if (pkt.icmph != NULL)
	{
		printICMP2TreeCtrl(pkt, parentNode);
	}
	else if (pkt.tcph != NULL)
	{
		printTCP2TreeCtrl(pkt, parentNode);
	}
	else if (pkt.udph != NULL)
	{
		printUDP2TreeCtrl(pkt, parentNode);
	}
	return 0;
}
int CSnifferUIDlg::printARP2TreeCtrl(const Packet &pkt, HTREEITEM &parentNode)
{
	if (pkt.isEmpty() || pkt.arph == NULL || parentNode == NULL)
		return -1;

	HTREEITEM ARPNode;
	CString strText, strTmp;

	switch (ntohs(pkt.arph->opcode))
	{
	case ARP_OPCODE_REQUET:
		strText.Format("ARP������)");
		break;
	case ARP_OPCODE_REPLY:
		strText.Format("ARP����Ӧ)");
		break;
	default:
		strText.Format("ARP");
		break;
	}
	ARPNode = m_treeCtrlPacketDetails.InsertItem(strText, 0, 0, parentNode, 0);

	strText.Format("Ӳ�����ͣ�%hu", ntohs(pkt.arph->hwtype));
	m_treeCtrlPacketDetails.InsertItem(strText, ARPNode, 0);

	strText.Format("Э�����ͣ�0x%04hx (%hu)", ntohs(pkt.arph->ptype), ntohs(pkt.arph->ptype));
	m_treeCtrlPacketDetails.InsertItem(strText, ARPNode, 0);

	strText.Format("Ӳ����ַ���ȣ�%u", pkt.arph->hwlen);
	m_treeCtrlPacketDetails.InsertItem(strText, ARPNode, 0);

	strText.Format("Э���ַ���ȣ�%u", pkt.arph->plen);
	m_treeCtrlPacketDetails.InsertItem(strText, ARPNode, 0);

	switch (ntohs(pkt.arph->opcode))
	{
	case ARP_OPCODE_REQUET:
		strText.Format("OP�룺����%hu��", ntohs(pkt.arph->opcode));
		break;
	case ARP_OPCODE_REPLY:
		strText.Format("OP�룺��Ӧ��%hu��", ntohs(pkt.arph->opcode));
		break;
	default:
		strText.Format("OP�룺δ֪��%hu��", ntohs(pkt.arph->opcode));
		break;
	}
	m_treeCtrlPacketDetails.InsertItem(strText, ARPNode, 0);

	strText = "ԴMAC��ַ��" + MACAddr2CString(pkt.arph->srcmac);
	m_treeCtrlPacketDetails.InsertItem(strText, ARPNode, 0);

	strText = "ԴIP��ַ��" + IPAddr2CString(pkt.arph->srcip);
	m_treeCtrlPacketDetails.InsertItem(strText, ARPNode, 0);

	strText = "Ŀ��MAC��ַ��" + MACAddr2CString(pkt.arph->dstmac);
	m_treeCtrlPacketDetails.InsertItem(strText, ARPNode, 0);

	strText = "Ŀ��IP��ַ��" + IPAddr2CString(pkt.arph->dstip);
	m_treeCtrlPacketDetails.InsertItem(strText, ARPNode, 0);

	return 0;
}
int CSnifferUIDlg::printICMP2TreeCtrl(const Packet &pkt, HTREEITEM &parentNode)
{
	if (pkt.isEmpty() || pkt.icmph == NULL || parentNode == NULL)
		return -1;

	HTREEITEM ICMPNode;
	CString strText, strTmp;

	strText = "ICMP";
	switch (pkt.icmph->type)
	{
	case ICMP_TYPE_ECHO_REPLY:
		strTmp = "����ӦӦ�𱨸棩";
		break;
	case ICMP_TYPE_DESTINATION_UNREACHABLE:
		strTmp = "�����޲��ɴﱨ�棩";
		break;
	case ICMP_TYPE_SOURCE_QUENCH:
		strTmp = "��Դ�����Ʊ��棩";
		break;
	case ICMP_TYPE_REDIRECT:
		strTmp = "���ض��򱨸棩";
		break;
	case ICMP_TYPE_ECHO:
		strTmp = "����Ӧ���󱨸棩";
		break;
	case ICMP_TYPE_ROUTER_ADVERTISEMENT:
		strTmp = "��·����ͨ�汨�棩";
		break;
	case ICMP_TYPE_ROUTER_SOLICITATION:
		strTmp = "��·����ѯ�ʱ��棩";
		break;
	case ICMP_TYPE_TIME_EXCEEDED:
		strTmp = "����ʱ���棩";
		break;
	case ICMP_TYPE_PARAMETER_PROBLEM:
		strTmp = "�����ݱ��������󱨸棩";
		break;
	case ICMP_TYPE_TIMESTAMP:
		strTmp = "��ʱ������󱨸棩";
		break;
	case ICMP_TYPE_TIMESTAMP_REPLY:
		strTmp = "��ʱ�����Ӧ���棩";
		break;
	default:
		strTmp.Format("��δ֪��");
		break;
	}
	strText += strTmp;
	ICMPNode = m_treeCtrlPacketDetails.InsertItem(strText, parentNode, 0);

	IP_Address addr = *(IP_Address *)&(pkt.icmph->others);
	u_short id = pkt.getICMPID();
	u_short seq = pkt.getICMPSeq();

	strText.Format("���ͣ�%u", pkt.icmph->type);
	m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

	switch (pkt.icmph->type)
	{
	case ICMP_TYPE_ECHO_REPLY:
	{
		strText = "���룺0";
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		strText.Format("У���:0x%04hX", ntohs(pkt.icmph->chksum));
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		strText.Format("��ʶ��%hu", id);
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		strText.Format("��ţ�%hu", seq);
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		break;
	}

	case ICMP_TYPE_DESTINATION_UNREACHABLE:
		strText = "���룺";
		switch (pkt.icmph->code)
		{
		case ICMP_TYPE_DESTINATION_UNREACHABLE_CODE_NET_UNREACHABLE:
			strText.Format("���粻�ɴ� ��%d��", pkt.icmph->code);
			break;

		case ICMP_TYPE_DESTINATION_UNREACHABLE_CODE_HOST_UNREACHABLE:
			strText.Format("�������ɴ� ��%d��", pkt.icmph->code);
			break;

		case ICMP_TYPE_DESTINATION_UNREACHABLE_CODE_PROTOCOL_UNREACHABLE:
			strText.Format("Э�鲻�ɴ� ��%d��", pkt.icmph->code);
			break;

		case ICMP_TYPE_DESTINATION_UNREACHABLE_CODE_PORT_UNREACHABLE:
			strText.Format("�˿ڲ��ɴ� ��%d��", pkt.icmph->code);
			break;

		case 6:
			strTmp = "��������δ֪ ��6��";
			break;

		case 7:
			strTmp = "��������δ֪ ��7��";
			break;

		default:
			strText.Format("δ֪ ��%d��", pkt.icmph->code);
			break;
		}
		strText += strTmp;
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		strText.Format("У��ͣ�0x%04hX", ntohs(pkt.icmph->chksum));
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);
		break;

	case ICMP_TYPE_SOURCE_QUENCH:
		strText.Format("���룺%d", ICMP_TYPE_SOURCE_QUENCH_CODE);
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		strText.Format("У��ͣ�0x%04hX", ntohs(pkt.icmph->chksum));
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);
		break;

	case ICMP_TYPE_REDIRECT:
		strText = "���룺";
		switch (pkt.icmph->code)
		{
		case ICMP_TYPE_REDIRECT_CODE_REDIRECT_DATAGRAMS_FOR_THE_NETWORK:
			strText.Format("���ض������ض���%d)", pkt.icmph->code);
			break;

		case ICMP_TYPE_REDIRECT_CODE_REDIRECT_DATAGRAMS_FOR_THE_HOST:
			strText.Format("���ض������ض��� ��%d)", pkt.icmph->code);
			break;

		case ICMP_TYPE_REDIRECT_CODE_REDIRECT_DATAGRAMS_FOR_THE_TOS_AND_NETWORK:
			strText.Format("����ָ���ķ������Ͷ��ض������ض��� ��%d��", pkt.icmph->code);
			break;

		case ICMP_TYPE_REDIRECT_CODE_REDIRECT_DATAGRAMS_FOR_THE_TOS_AND_HOST:
			strText.Format("����ָ���ķ������Ͷ��ض������ض��� ��%d��", pkt.icmph->code);
			break;
		}
		strText += strTmp;
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		strText.Format("У��ͣ�0x%04hx", ntohs(pkt.icmph->chksum));
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		strText = "Ŀ��·������IP��ַ��" + IPAddr2CString(addr);
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);
		break;

	case ICMP_TYPE_ECHO:
		strText.Format("���룺%d", pkt.icmph->code);
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		strText.Format("У��ͣ�0x%04hX", ntohs(pkt.icmph->chksum));
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		strText.Format("��ʶ��%hu", id);
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		strText.Format("��ţ�%hu", seq);
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);
		break;

	case ICMP_TYPE_TIME_EXCEEDED:
		strText = "���룺";
		switch (pkt.icmph->code)
		{
		case ICMP_TYPE_TIME_EXCEEDED_CODE_TTL_EXCEEDED_IN_TRANSIT:
			strText.Format("TTL��ʱ ��%d��", pkt.icmph->code);
			break;
		case ICMP_TYPE_TIME_EXCEEDED_CODE_FRAGMENT_REASSEMBLY_TIME_EXCEEDE:
			strText.Format("��Ƭ���鳬ʱ ��%d��", pkt.icmph->code);
			break;
		}
		strText += strTmp;
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		strText.Format("У��ͣ�0x%04hx", ntohs(pkt.icmph->chksum));
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		break;

	default:
		strText.Format("���룺%d", pkt.icmph->code);
		m_treeCtrlPacketDetails.InsertItem(strText, 0, 0, ICMPNode, 0);

		strText.Format("У��ͣ�0x%04hX", pkt.icmph->chksum);
		m_treeCtrlPacketDetails.InsertItem(strText, 0, 0, ICMPNode, 0);

		break;
	}
	return 0;
}
int CSnifferUIDlg::printTCP2TreeCtrl(const Packet &pkt, HTREEITEM &parentNode)
{
	if (pkt.isEmpty() || pkt.tcph == NULL || parentNode == NULL)
	{
		return -1;
	}
	HTREEITEM TCPNode;
	CString strText, strTmp;

	strText.Format("TCP��%hu -> %hu��", ntohs(pkt.tcph->srcport), ntohs(pkt.tcph->dstport));
	TCPNode = m_treeCtrlPacketDetails.InsertItem(strText, parentNode, 0);

	strText.Format("Դ�˿ڣ�%hu", ntohs(pkt.tcph->srcport));
	m_treeCtrlPacketDetails.InsertItem(strText, TCPNode, 0);

	strText.Format("Ŀ�Ķ˿ڣ�%hu", ntohs(pkt.tcph->dstport));
	m_treeCtrlPacketDetails.InsertItem(strText, TCPNode, 0);

	strText.Format("���кţ�0x%0lX", ntohl(pkt.tcph->seq));
	m_treeCtrlPacketDetails.InsertItem(strText, TCPNode, 0);

	strText.Format("ȷ�Ϻţ�0x%0lX", ntohl(pkt.tcph->ack));
	m_treeCtrlPacketDetails.InsertItem(strText, TCPNode, 0);

	strText.Format("�ײ����ȣ�%d �ֽڣ�%d��", pkt.getTCPHeaderLength(), pkt.getTCPHeaderLengthRaw());
	m_treeCtrlPacketDetails.InsertItem(strText, TCPNode, 0);

	strText.Format("��־��0x%03X", pkt.getTCPFlags());
	HTREEITEM TCPFlagNode = m_treeCtrlPacketDetails.InsertItem(strText, TCPNode, 0);

	strText.Format("URG��%d", pkt.getTCPFlagsURG());
	m_treeCtrlPacketDetails.InsertItem(strText, TCPFlagNode, 0);

	strText.Format("ACK��%d", pkt.getTCPFlagsACK());
	m_treeCtrlPacketDetails.InsertItem(strText, TCPFlagNode, 0);

	strText.Format("PSH��%d", pkt.getTCPFlagsPSH());
	m_treeCtrlPacketDetails.InsertItem(strText, TCPFlagNode, 0);

	strText.Format("RST��%d", pkt.getTCPFlagsRST());
	m_treeCtrlPacketDetails.InsertItem(strText, TCPFlagNode, 0);

	strText.Format("SYN��%d", pkt.getTCPFlagsSYN());
	m_treeCtrlPacketDetails.InsertItem(strText, TCPFlagNode, 0);

	strText.Format("FIN��%d", pkt.getTCPFlagsFIN());
	m_treeCtrlPacketDetails.InsertItem(strText, TCPFlagNode, 0);

	strText.Format("���ڴ�С��%hu", ntohs(pkt.tcph->win_size));
	m_treeCtrlPacketDetails.InsertItem(strText, TCPNode, 0);

	strText.Format("У��ͣ�0x%04hX", ntohs(pkt.tcph->chksum));
	m_treeCtrlPacketDetails.InsertItem(strText, TCPNode, 0);

	strText.Format("����ָ�룺%hu", ntohs(pkt.tcph->urg_ptr));
	m_treeCtrlPacketDetails.InsertItem(strText, TCPNode, 0);

	if (pkt.dnsh != NULL)
	{
		printDNS2TreeCtrl(pkt, parentNode);
	}
	else if (pkt.dhcph != NULL)
	{
		printDHCP2TreeCtrl(pkt, parentNode);
	}
	else if (pkt.httpmsg != NULL)
	{
		printHTTP2TreeCtrl(pkt, parentNode);
	}

	return 0;
}
int CSnifferUIDlg::printUDP2TreeCtrl(const Packet &pkt, HTREEITEM &parentNode)
{
	if (pkt.isEmpty() || pkt.udph == NULL || parentNode == NULL)
	{
		return -1;
	}
	HTREEITEM UDPNode;
	CString strText, strTmp;

	strText.Format("UDP��%hu -> %hu��", ntohs(pkt.udph->srcport), ntohs(pkt.udph->dstport));
	UDPNode = m_treeCtrlPacketDetails.InsertItem(strText, parentNode, 0);

	strText.Format("Դ�˿ڣ�%hu", ntohs(pkt.udph->srcport));
	m_treeCtrlPacketDetails.InsertItem(strText, UDPNode, 0);

	strText.Format("Ŀ�Ķ˿ڣ�%hu", ntohs(pkt.udph->dstport));
	m_treeCtrlPacketDetails.InsertItem(strText, UDPNode, 0);

	strText.Format("���ȣ�%hu", ntohs(pkt.udph->len));
	m_treeCtrlPacketDetails.InsertItem(strText, UDPNode, 0);

	strText.Format("У��ͣ�0x%04hX", ntohs(pkt.udph->checksum));
	m_treeCtrlPacketDetails.InsertItem(strText, UDPNode, 0);

	if (pkt.dnsh != NULL)
	{
		// printDNS2TreeCtrl(pkt, parentNode);
	}
	else if (pkt.dhcph != NULL)
	{
		printDHCP2TreeCtrl(pkt, parentNode);
	}
	return 0;
}
HTREEITEM CSnifferUIDlg::printDNSBanner(const Packet &pkt, HTREEITEM &parentNode)
{
	if (pkt.isEmpty() || parentNode == NULL)
	{
		return NULL;
	}
	CString strText;

	switch (pkt.getDNSFlagsQR())
	{
	case DNS_FLAGS_QR_REQUEST:
		strText = "DNS������";
		break;
	case DNS_FLAGS_QR_REPLY:
		strText = "DNS����Ӧ��";
		break;
	}
	return m_treeCtrlPacketDetails.InsertItem(strText, parentNode, 0);
}

	/**
	 * @brief ��ӡDNSͷ����Ϣ�����οؼ�
	 * @param [in] pkt ���ݰ�����
	 * @param [in] parentNode ���οؼ����ڵ�
	 * @return 0 �ɹ���-1 ʧ�ܣ����ݰ�Ϊ�ջ���DNSͷ����
	 */
int CSnifferUIDlg::printDNSHeader(const Packet &pkt, HTREEITEM &parentNode)
{
	if (pkt.isEmpty() || pkt.dnsh == NULL || parentNode == NULL)
	{
		return -1;
	}
	CString strText, strTmp;
	// ��ӡDNS��ʶ�ֶ�
	strText.Format("��ʶ��0x%04hX (%hu)", ntohs(pkt.dnsh->identifier), ntohs(pkt.dnsh->identifier));
	m_treeCtrlPacketDetails.InsertItem(strText, parentNode, 0);

	strText.Format("��־��0x%04hX", ntohs(pkt.dnsh->flags));
	strText += strTmp;

	HTREEITEM DNSFlagNode = m_treeCtrlPacketDetails.InsertItem(strText, parentNode, 0);
	/* ��־���ֶ� */
	switch (pkt.getDNSFlagsQR())
	{
	case DNS_FLAGS_QR_REQUEST:
		strText = "QR��; ��ѯ���� ��0��";
		break;
	case DNS_FLAGS_QR_REPLY:
		strText = "QR��; ��Ӧ���� ��1��";
		break;
	}
	m_treeCtrlPacketDetails.InsertItem(strText, DNSFlagNode, 0);

	switch (pkt.getDNSFlagsOPCODE())
	{
	case DNS_FLAGS_OPCODE_STANDARD_QUERY:
		strText = "OPCODE����׼��ѯ ��0��";
		break;
	case DNS_FLAGS_OPCODE_INVERSE_QUERY:
		strText = "OPCODE�������ѯ ��1��";
		break;
	case DNS_FLAGS_OPCODE_SERVER_STATUS_REQUEST:
		strText = "OPCODE��������״̬���� ��2��";
		break;
	}
	m_treeCtrlPacketDetails.InsertItem(strText, DNSFlagNode, 0);

	switch (pkt.getDNSFlagsAA())
	{
	case 0:
		strText = "AA������Ȩ�ش� ��0��";
		break;
	case 1:
		strText = "AA����Ȩ�ش� ��1��";
		break;
	}
	m_treeCtrlPacketDetails.InsertItem(strText, DNSFlagNode, 0);

	switch (pkt.getDNSFlagsTC())
	{
	case 0:
		strText = "TC������δ�ض� ��0��";
		break;
	case 1:
		strText = "TC�����Ľض� ��1��";
		break;
	}
	m_treeCtrlPacketDetails.InsertItem(strText, DNSFlagNode, 0);

	switch (pkt.getDNSFlagsRD())
	{
	case 0:
		strText = "RD��0";
		break;
	case 1:
		strText = "RD��ϣ�����еݹ��ѯ ��1��";
		break;
	}
	m_treeCtrlPacketDetails.InsertItem(strText, DNSFlagNode, 0);

	switch (pkt.getDNSFlagsRA())
	{
	case 0:
		strText = "RA����������֧�ֵݹ��ѯ ��0��";
		break;
	case 1:
		strText = "RA��������֧�ֵݹ��ѯ ��1��";
		break;
	}
	m_treeCtrlPacketDetails.InsertItem(strText, DNSFlagNode, 0);

	strText.Format("Z��������%d��", pkt.getDNSFlagsZ());
	m_treeCtrlPacketDetails.InsertItem(strText, DNSFlagNode, 0);

	switch (pkt.getDNSFlagsRCODE())
	{
	case DNS_FLAGS_RCODE_NO_ERROR:
		strText = "RCODE���޲�� ��0��";
		break;
	case DNS_FLAGS_RCODE_FORMAT_ERROR:
		strText = "RCODE����ʽ��� ��1��";
		break;
	case DNS_FLAGS_RCODE_SERVER_FAILURE:
		strText = "RCODE��DNS���������� ��2��";
		break;
	case DNS_FLAGS_RCODE_NAME_ERROR:
		strText = "RCODE�����������ڻ���� ��3��";
		break;
	case DNS_FLAGS_RCODE_NOT_IMPLEMENTED:
		strText = "RCODE����ѯ���Ͳ�֧�� ��4��";
		break;
	case DNS_FLAGS_RCODE_REFUSED:
		strText = "RCODE���ڹ����Ͻ�ֹ ��5��";
		break;
	default:
		strText.Format("RCODE��������%d��", pkt.getDNSFlagsRCODE());
		break;
	}
	m_treeCtrlPacketDetails.InsertItem(strText, DNSFlagNode, 0);

	strText.Format("��ѯ��¼����%hu", ntohs(pkt.dnsh->questions));
	m_treeCtrlPacketDetails.InsertItem(strText, parentNode, 0);

	strText.Format("�ش��¼����%hu", ntohs(pkt.dnsh->answer_RRs));
	m_treeCtrlPacketDetails.InsertItem(strText, parentNode, 0);

	strText.Format("��Ȩ�ش��¼����%hu", ntohs(pkt.dnsh->authority_RRs));
	m_treeCtrlPacketDetails.InsertItem(strText, parentNode, 0);

	strText.Format("������Ϣ��¼����%hu", ntohs(pkt.dnsh->additional_RRs));
	m_treeCtrlPacketDetails.InsertItem(strText, parentNode, 0);

	return 0;
}

	/**
	 * @brief ��DNS����ö��ֵת��Ϊ�ַ�������
	 * @param [in] type DNS����ֵ�������ֽ���
	 * @return ���Ͷ�Ӧ���ַ�������
	 */
CString CSnifferUIDlg::DNSType2CString(const u_short &type)
{
	CString strType;
	// ����DNS����ö��ֵ���ض�Ӧ����
	switch (ntohs(type))
	{
	case DNS_TYPE_A:
		strType = "Type A��IPv4��ַ��¼��";
		break;
	case DNS_TYPE_NS:
		strType = "Type NS�����Ʒ�������¼��";
		break;
	case DNS_TYPE_CNAME:
		strType = "Type CNAME";
		break;
	case DNS_TYPE_SOA:
		strType = "Type SOA";
		break;
	case DNS_TYPE_PTR:
		strType = "Type PTR";
		break;
	case DNS_TYPE_MX:
		strType = "Type MX";
		break;
	case DNS_TYPE_AAAA:
		strType = "Type AAAA";
		break;
	case DNS_TYPE_ANY:
		strType = "Type ANY";
		break;
	default:
		strType.Format(" Type δ֪��%hu��,", ntohs(type));
		break;
	}
	return strType;
}
CString CSnifferUIDlg::DNSClass2CString(const u_short &classes)
{
	CString strClass;
	switch (ntohs(classes))
	{
	case DNS_CLASS_IN:
		strClass = "Class IN";
		break;
	case DNS_CLASS_CS:
		strClass = "Class CS";
		break;
	case DNS_CLASS_HS:
		strClass = "Class HS";
		break;
	default:
		strClass.Format("Class δ֪��%hu��", ntohs(classes));
		break;
	}
	return strClass;
}

	/**
	 * @brief ��ӡDNS��ѯ������Ϣ�����οؼ�
	 * @param [in] DNSQuery DNS��ѯ����ָ��
	 * @param [in] questions ��ѯ��¼��
	 * @param [in] parentNode ���οؼ����ڵ�
	 * @return ������ֽ�����-1 ʧ�ܣ�����Ϊ�գ�
	 */
int CSnifferUIDlg::printDNSQuery(char *DNSQuery, const u_short &questions, HTREEITEM &parentNode)
{
	if (DNSQuery == NULL && parentNode == NULL)
	{
		return -1;
	}
	CString strText, strTmp;
	// ������ѯ���ָ��ڵ�
	HTREEITEM DNSQueryNode = m_treeCtrlPacketDetails.InsertItem("��ѯ���֣�", parentNode, 0);

	/* ��ѯ���� */

	char *p = DNSQuery;
	// if (questions < 10)
	//{
	for (int queryNum = 0; queryNum < questions; ++queryNum)
	{
		char *name = (char *)malloc(strlen(p) + 1);
		translateNameInDNS(name, p);

		/* ���������ֶ� */
		p += strlen(p) + 1;
		strText.Format("%s��", name);

		DNS_Query *DNSQuery = (DNS_Query *)p;
		strText += DNSType2CString(DNSQuery->type) + ", ";
		strText += DNSClass2CString(DNSQuery->classes);
		m_treeCtrlPacketDetails.InsertItem(strText, DNSQueryNode, 0);

		/* ������ѯ���ͺͲ�ѯ���ֶ� */
		p += sizeof(DNS_Query);
		free(name);
	} // for
	//}// if
	return p - DNSQuery + 1;
}
int CSnifferUIDlg::printDNSResourceRecord(char *DNSResourceRecord, const u_short &resourceRecordNum, const int &resourceRecordType, const DNS_Header *pDNSHeader, HTREEITEM parentNode)
{
	if (DNSResourceRecord == NULL || resourceRecordNum == 0 || pDNSHeader == NULL || parentNode == NULL)
	{
		return -1;
	}
	char *p = DNSResourceRecord;
	CString strText, strTmp;

	switch (resourceRecordType)
	{
	case DNS_RESOURCE_RECORD_TYPE_ANSWER:
		strText = "�ش𲿷֣�";
		break;
	case DNS_RESOURCE_RECORD_TYPE_AUTHORITY:
		strText = "��Ȩ�ش𲿷֣�";
		break;
	case DNS_RESOURCE_RECORD_TYPE_ADDITIONAL:
		strText = "������Ϣ���֣�";
		break;
	}
	HTREEITEM DNSResourceRecordNode = m_treeCtrlPacketDetails.InsertItem(strText, parentNode, 0);

	for (int count = 0; count < 1; ++count) // count < resourceRecordNum; ++count)
	{

		if (*(u_char *)p == 0xC0)
		{
			// name
			strText = getNameInDNS(p, pDNSHeader) + "��";

			// ָ��type��class��ttl
			p += 2; // 2 = 0xC0 + ƫ����
		}
		else
		{
			char *name = (char *)malloc(strlen(p) + 1);
			translateNameInDNS(name, p);

			CString strText, strTmp;
			strText.Format("%s: ", name);
			if (name != nullptr)
			{
				p += strlen(name) + 1;
			}
			else
			{
				p += 1;
			}
			free(name);
		}

		DNS_ResourceRecord *pRecord = (DNS_ResourceRecord *)p;
		strText += DNSType2CString(pRecord->type) + ", ";
		strText += DNSClass2CString(pRecord->classes) + ", ";
		strTmp.Format("TTL %d", ntohl(pRecord->ttl));
		strText += strTmp + ", ";

		// ָ����Դ���ݳ���
		p += sizeof(DNS_ResourceRecord);
		u_short dataLength = *(u_short *)p;
		strTmp.Format("��Դ���ݳ��ȣ�%hu �ֽ�", dataLength);
		strText += strTmp + ", ";

		// ָ����Դ����
		p += sizeof(u_short);

		switch (ntohs(pRecord->type))
		{
		case DNS_TYPE_A:
			strText += "IP��ַ�� " + IPAddr2CString(*(IP_Address *)p);
			break;
		case DNS_TYPE_NS:
			strText += "���ַ������� " + IPAddr2CString(*(IP_Address *)p);
			break;
		case DNS_TYPE_CNAME:
		{

			CString strCName = getNameInDNS(p, pDNSHeader);
			strText += "������" + strCName;
			// m_treeCtrlPacketDetails.InsertItem(strText, parentNode, 0);
			// free(cname);
			break;
		}
		default:
			/*strTmp.Format("Type δ֪(%hu),", ntohs(pRecord->type));
			strText += strTmp;*/
			break;
		}
		m_treeCtrlPacketDetails.InsertItem(strText, DNSResourceRecordNode, 0);

	} // for
	return p - DNSResourceRecord + 1;
}
int CSnifferUIDlg::printDNS2TreeCtrl(const Packet &pkt, HTREEITEM &parentNode)
{
	if (pkt.isEmpty() || pkt.dnsh == NULL || parentNode == NULL)
	{
		return -1;
	}
	HTREEITEM DNSNode = printDNSBanner(pkt, parentNode);

	printDNSHeader(pkt, DNSNode);

	char *DNSQuery = (char *)pkt.dnsh + DNS_HEADER_LENGTH;
	int DNSQueryLen = printDNSQuery(DNSQuery, ntohs(pkt.dnsh->questions), DNSNode);

	char *DNSAnswer = NULL, *DNSAuthority = NULL, *DNSAdditional = NULL;
	int DNSAnswerLen = 0, DNSAuthorityLen = 0;

	if (ntohs(pkt.dnsh->answer_RRs) > 0)
	{
		DNSAnswer = DNSQuery + DNSQueryLen;
		DNSAnswerLen = printDNSResourceRecord(DNSAnswer, ntohs(pkt.dnsh->answer_RRs), DNS_RESOURCE_RECORD_TYPE_ANSWER, pkt.dnsh, DNSNode);
	}

	if (ntohs(pkt.dnsh->authority_RRs) > 0)
	{
		DNSAuthority = DNSAnswer + DNSAnswerLen;
		DNSAuthorityLen = printDNSResourceRecord(DNSAuthority, ntohs(pkt.dnsh->authority_RRs), DNS_RESOURCE_RECORD_TYPE_AUTHORITY, pkt.dnsh, DNSNode);
	}

	if (ntohs(pkt.dnsh->additional_RRs) > 0)
	{
		DNSAdditional = DNSAuthority + DNSAuthorityLen;
		printDNSResourceRecord(DNSAdditional, ntohs(pkt.dnsh->additional_RRs), DNS_RESOURCE_RECORD_TYPE_ADDITIONAL, pkt.dnsh, DNSNode);
	}

	return 0;
}
int CSnifferUIDlg::printDHCP2TreeCtrl(const Packet &pkt, HTREEITEM &parentNode)
{
	if (pkt.isEmpty() || pkt.dhcph == NULL || parentNode == NULL)
	{
		return -1;
	}
	HTREEITEM DHCPNode = nullptr;
	if (parentNode != nullptr)
	{
		DHCPNode = m_treeCtrlPacketDetails.InsertItem("DHCP", parentNode, 0);
	}
	else
	{
		AfxMessageBox(_T("Error: parentNode is null. Cannot insert item into tree control."), MB_OK | MB_ICONERROR);
	}
	CString strText, strTmp;
	/* ����dhcp�ײ� */
	strText.Format("�������ͣ�%d", pkt.dhcph->op);
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);
	strText.Format("Ӳ�����ͣ�%d", pkt.dhcph->htype);
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	strText.Format("Ӳ����ַ���ȣ�%d", pkt.dhcph->hlen);
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	strText.Format("������%d", pkt.dhcph->hops);
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	strText.Format("����ID��0x%08lX", ntohl(pkt.dhcph->xid));
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	strText.Format("�ͻ�����ʱ�䣺%hu", ntohs(pkt.dhcph->secs));
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	strText.Format("��־��0x%04hX", ntohs(pkt.dhcph->flags));
	switch (ntohs(pkt.dhcph->flags) >> 15)
	{
	case DHCP_FLAGS_BROADCAST:
		strText += "���㲥��";
		break;
	case DHCP_FLAGS_UNICAST:
		strText += "��������";
		break;
	}
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	strText = "�ͻ���IP��ַ��" + IPAddr2CString(pkt.dhcph->ciaddr);
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	strText = "��ģ��ͻ���IP��ַ��" + IPAddr2CString(pkt.dhcph->yiaddr);
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	strText = "������IP��ַ��" + IPAddr2CString(pkt.dhcph->siaddr);
	;
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	strText = "����IP��ַ��" + IPAddr2CString(pkt.dhcph->giaddr);
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	/*  ����dhcp�ײ�ʣ�ಿ�� */
	CString strChaddr;
	for (int i = 0; i < 6; ++i)
	{
		strTmp.Format("%02X", pkt.dhcph->chaddr[i]);
		strChaddr += strTmp + "-";
	}
	strChaddr.Delete(strChaddr.GetLength() - 1, 1);

	strText = "�ͻ���MAC��ַ��" + strChaddr;
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	strText = "��������������";
	strTmp.Format("%s", pkt.dhcph->snamer);
	strText += strTmp;
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	strText = "�����ļ�����";
	strTmp.Format("%s", pkt.dhcph->file);
	strText += strTmp;
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	// ���������ļ���
	u_char *p = (u_char *)pkt.dhcph->file + 128;

	if (ntohl(*(u_long *)p) == 0x63825363)
	{
		strText = "Magic cookie: DHCP";
		m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);
	}

	// ����magic cookie
	p += 4;

	while (*p != 0xFF)
	{
		switch (*p)
		{
		case DHCP_OPTIONS_DHCP_MESSAGE_TYPE:
		{
			strText = "ѡ���53��DHCP��������";
			switch (*(p + 2))
			{
			case 1:
				strText += "��Discover��";
				break;
			case 2:
				strText += "��Offer��";
				break;
			case 3:
				strText += "��Request��";
				break;
			case 4:
				strText += "��Decline��";
				break;
			case 5:
				strText += "��ACK��";
				break;
			case 6:
				strText += "��NAK��";
				break;
			case 7:
				strText += "��Release��";
				break;
			case 8:
				strText += "��Inform��";
				break;
			}
			HTREEITEM DHCPOptionNode = m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

			strText.Format("���ȣ�%d", *(++p));
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			strText.Format("DHCP��%d", *(++p));
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			// ָ����һ��ѡ��
			++p;
		}
		break;

		case DHCP_OPTIONS_REQUESTED_IP_ADDRESS:
		{
			strText = "ѡ���50������IP��ַ";
			HTREEITEM DHCPOptionNode = m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

			strText.Format("���ȣ�%d", *(++p));
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			IP_Address *addr = (IP_Address *)(++p);
			strText = "��ַ��" + IPAddr2CString(*addr);
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			// ָ����һ��ѡ��
			p += 4;
		}
		break;

		case DHCP_OPTIONS_IP_ADDRESS_LEASE_TIME:
		{
			strText = "ѡ���51��IP��ַ��Լʱ��";
			HTREEITEM DHCPOptionNode = m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

			strText.Format("���ȣ�%d", *(++p));
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			u_int time = *(++p);
			strText.Format("��Լʱ�䣺%u", time);
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			// ָ����һ��ѡ��
			p += 4;
		}
		break;

		case DHCP_OPTIONS_CLIENT_IDENTIFIER:
		{
			strText = "ѡ���61���ͻ�����ʶ";
			HTREEITEM DHCPOptionNode = m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format("���ȣ�%d", len);
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			strText = "Ӳ�����ͣ�";
			if (*(++p) == 0x01)
			{
				strText += "��̫����0x01��";
				m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

				MAC_Address *addr = (MAC_Address *)(++p);
				strText = "�ͻ�����ʶ��" + MACAddr2CString(*addr);
				m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

				p += 6;
			}
			else
			{
				strText.Format("%d", *p);
				strText += strTmp;
				m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

				p += len;
			}
		}
		break;

		case DHCP_OPTIONS_VENDOR_CLASS_IDENTIFIER:
		{
			strText = "ѡ���60����Ӧ�����ʶ";
			HTREEITEM DHCPOptionNode = m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format("���ȣ�%d", len);
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			int count = 0;
			strText = "��Ӧ�����ʶ��";
			for (; count < len; count++)
			{
				strTmp.Format("%c", *(++p));
				strText += strTmp;
			}
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			++p;
		}
		break;

		case DHCP_OPTIONS_SERVER_IDENTIFIER:
		{
			strText = "ѡ���54����������ʶ";
			HTREEITEM DHCPOptionNode = m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format("���ȣ�%d", len);
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			IP_Address *addr = (IP_Address *)(++p);
			strText = "��������ʶ��" + IPAddr2CString(*addr);
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			p += 4;
		}
		break;

		case DHCP_OPTIONS_SUBNET_MASK:
		{

			strText = "ѡ���1����������";
			HTREEITEM DHCPOptionNode = m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format("���ȣ�%d", len);
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			IP_Address *submask = (IP_Address *)(++p);
			strText = "�������룺" + IPAddr2CString(*submask);
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			p += 4;
		}
		break;

		case DHCP_OPTIONS_ROUTER_OPTION:
		{

			strText = "ѡ���3��·����";
			HTREEITEM DHCPOptionNode = m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format("���ȣ�%d", len);
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			int count = 0;
			while (count < len)
			{
				IP_Address *addr = (IP_Address *)(++p);
				strText = "·������" + IPAddr2CString(*addr);
				m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

				count += 4;
				p += 4;
			}
		}
		break;

		case DHCP_OPTIONS_DOMAIN_NAME_SERVER_OPTION:
		{
			strText = "ѡ���6��DNS������";
			HTREEITEM DHCPOptionNode = m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format("���ȣ�%d", len);
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			int count = 0;
			++p;
			while (count < len)
			{
				IP_Address *addr = (IP_Address *)(p);
				strText = "DNS��������" + IPAddr2CString(*addr);
				m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

				count += 4;
				p += 4;
			}
		}
		break;

		case DHCP_OPTIONS_HOST_NAME_OPTION:
		{
			strText = "ѡ���12��������";
			HTREEITEM DHCPOptionNode = m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format("���ȣ�%d", len);
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			int count = 0;
			strText = "��������";

			for (; count < len; count++)
			{
				strTmp.Format("%c", *(++p));
				strText += strTmp;
			}
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			++p;
		}
		break;

		case DHCP_OPTIONS_PAD_OPTION:
			++p;
			break;

		default:
		{
			strText.Format("ѡ���%d��", *p);
			HTREEITEM DHCPOptionNode = m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format("���ȣ�%d", len);
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			// ָ��ѡ������
			++p;

			// ����ѡ������
			p += len;
		}
		break;
		} // switch

	} // while
	strText = "ѡ���255������";
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	return 0;
}
int CSnifferUIDlg::printHTTP2TreeCtrl(const Packet &pkt, HTREEITEM &parentNode)
{
	if (pkt.isEmpty() || pkt.httpmsg == NULL || parentNode == NULL)
	{
		return -1;
	}

	u_char *p = pkt.httpmsg;
	int HTTPMsgLen = pkt.getL4PayloadLength();

	CString strText;
	if (ntohs(pkt.tcph->dstport) == PORT_HTTP)
	{
		strText = "HTTP������";
	}
	else if (ntohs(pkt.tcph->srcport) == PORT_HTTP)
	{
		strText = "HTTP����Ӧ��";
	}
	HTREEITEM HTTPNode;
	if (parentNode != NULL)
	{
		HTTPNode = m_treeCtrlPacketDetails.InsertItem(strText, parentNode, 0);
	}
	else
	{
		HTTPNode = m_treeCtrlPacketDetails.InsertItem(strText, TVI_ROOT, 0);
	}
	for (int count = 0; count < HTTPMsgLen;)
	{
		strText = "";
		while (*p != '\r')
		{
			strText += *p;
			++p;
			++count;
		}
		strText += "\\r\\n";
		m_treeCtrlPacketDetails.InsertItem(strText, HTTPNode, 0);

		p += 2;
		count += 2;
	}
	return 0;
}
CString CSnifferUIDlg::MACAddr2CString(const MAC_Address &addr)
{
	CString strAddr, strTmp;

	for (int i = 0; i < 6; ++i)
	{
		strTmp.Format("%02X", addr.bytes[i]);
		strAddr += strTmp + "-";
	}
	strAddr.Delete(strAddr.GetLength() - 1, 1);

	return strAddr;
}
CString CSnifferUIDlg::IPAddr2CString(const IP_Address &addr)
{
	CString strAddr, strTmp;

	for (int i = 0; i < 4; ++i)
	{
		strTmp.Format("%d", addr.bytes[i]);
		strAddr += strTmp + ".";
	}
	strAddr.Delete(strAddr.GetLength() - 1, 1);

	return strAddr;
}
void CSnifferUIDlg::OnClickedList1(NMHDR *pNMHDR, LRESULT *pResult)
{
	/* ��ȡѡ���е��к� */
	int selectedItemIndex = m_listCtrlPacketList.GetSelectionMark();
	CString strPktNum = m_listCtrlPacketList.GetItemText(selectedItemIndex, 0);
	int pktNum = _ttoi(strPktNum);
	if (pktNum < 1 || pktNum > m_pool.getSize())
		return;
	const Packet &pkt = m_pool.get(pktNum);

	printTreeCtrlPacketDetails(pkt);
	printEditCtrlPacketBytes(pkt);
}
void CSnifferUIDlg::OnCustomdrawList1(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLVCUSTOMDRAW pNMCD = (LPNMLVCUSTOMDRAW)pNMHDR;
	*pResult = 0;

	if (CDDS_PREPAINT == pNMCD->nmcd.dwDrawStage)
	{
		*pResult = CDRF_NOTIFYITEMDRAW;
	}
	else if (CDDS_ITEMPREPAINT == pNMCD->nmcd.dwDrawStage) // һ��Item(һ��)���滭ǰ
	{
		COLORREF itemColor;

		CString *pStrPktProtocol = (CString *)(pNMCD->nmcd.lItemlParam); // ��printListCtrlPacketList(pkt)�ｫ���ݰ���protocol�ֶδ��ݹ���
		if (!pStrPktProtocol->IsEmpty())
		{
			if (*pStrPktProtocol == "ARP")
			{
				itemColor = RGB(255, 182, 193); // ��ɫ
			}
			else if (*pStrPktProtocol == "ICMP")
			{
				itemColor = RGB(186, 85, 211); // ��ɫ
			}
			else if (*pStrPktProtocol == "TCP")
			{
				itemColor = RGB(144, 238, 144); // ��ɫ
			}
			else if (*pStrPktProtocol == "UDP")
			{
				itemColor = RGB(100, 149, 237); // ��ɫ
			}
			else if (*pStrPktProtocol == "DNS")
			{
				itemColor = RGB(135, 206, 250); // ǳ��ɫ
			}
			else if (*pStrPktProtocol == "DHCP")
			{
				itemColor = RGB(189, 254, 76); // ����ɫ
			}
			else if (*pStrPktProtocol == "HTTP")
			{
				itemColor = RGB(238, 232, 180); // ��ɫ
			}
			else
			{
				itemColor = RGB(211, 211, 211); // ��ɫ
			}
			pNMCD->clrTextBk = itemColor;
		}
		*pResult = CDRF_DODEFAULT;
	}
}
LRESULT CSnifferUIDlg::OnPktCatchMessage(WPARAM wParam, LPARAM lParam)
{
	int pktNum = lParam;
	if (pktNum > 0)
	{
		Packet &pkt = m_pool.get(pktNum);
		/* ���������Ƿ��������������ˣ���ֻ��ӡ���Ϲ��������²������ݰ� */
		int selFilterIndex = m_comboBoxFilterList.GetCurSel();
		if (selFilterIndex > 0)
		{
			CString strFilter;
			m_comboBoxFilterList.GetLBText(selFilterIndex, strFilter);
			if (strFilter == pkt.protocol)
				printListCtrlPacketList(pkt);
		}
		else
			printListCtrlPacketList(pkt);

		// �޸�״̬�� - ���ݰ����������ݰ���ʾ����
		updateStatusBar(CString(""), m_pool.getSize(), m_listCtrlPacketList.GetItemCount());
	}

	return 0;
}
LRESULT CSnifferUIDlg::OnTExitMessage(WPARAM wParam, LPARAM lParam)
{
	m_catcher.closeAdapter();
	return 0;
}
BOOL CSnifferUIDlg::OnToolTipText(UINT, NMHDR *pNMHDR, LRESULT *pResult)
{
	TOOLTIPTEXT *pTTT = (TOOLTIPTEXT *)pNMHDR;
	UINT uID = pNMHDR->idFrom; // �൱��ԭWM_COMMAND���ݷ�ʽ��wParam��low-order��, ��wParam�зŵ����ǿؼ���ID��

	if (pTTT->uFlags & TTF_IDISHWND)
		uID = ::GetDlgCtrlID((HWND)uID);
	if (uID == NULL)
		return FALSE;
	switch (uID)
	{
	case ID_TOOLBARBTN_START:
		pTTT->lpszText = _T("��ʼ����");
		break;

	case ID_TOOLBARBTN_STOP:
		pTTT->lpszText = _T("��������");
		break;

	case ID_MENU_FILE_OPEN:
		pTTT->lpszText = _T("���ļ�");
		break;

	case ID_MENU_FILE_SAVEAS:
		pTTT->lpszText = _T("���Ϊ");
		break;

	case ID_TOOLBARBTN_CLEAR:
		pTTT->lpszText = _T("���������");
		break;

	case ID_TOOLBARBTN_FILTER:
		pTTT->lpszText = _T("Ӧ�ù�����");
		break;
	}

	return TRUE;
}
void CSnifferUIDlg::OnAcceleratorCtrlG()
{
	m_listCtrlPacketList.SetFocus();

	/* ��ֱ�������Զ�����ѡ��λ��*/
	int selItemIndex = m_listCtrlPacketList.GetSelectionMark();
	int topItemIndex = m_listCtrlPacketList.GetTopIndex(); // �б��е�ǰ���ɼ�����±�
	CRect rc;
	m_listCtrlPacketList.GetItemRect(selItemIndex, rc, LVIR_BOUNDS); // ���һ�еĴ�Сrc
	CSize sz(0, (selItemIndex - topItemIndex) * rc.Height());				 // ��selItemIndex - topItemIndex����ʾ������n��>0��ʾ���¹���n�У�<0��ʾ���Ϲ���n�У�
	// *rc.Height���иߣ�����Ϊscroll����������ֵ����
	m_listCtrlPacketList.Scroll(sz); // ������ѡ��λ��
}
void CSnifferUIDlg::OnKeydownList1(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLVKEYDOWN pLVKeyDow = reinterpret_cast<LPNMLVKEYDOWN>(pNMHDR);
	bool selectedItemChangedFlag = false;
	int selectedItemIndex = m_listCtrlPacketList.GetSelectionMark();
	/* �жϰ��µļ��Ƿ�Ϊ������ϻ������*/
	switch (pLVKeyDow->wVKey)
	{
	case VK_UP:
	{
		if (selectedItemIndex > 0 && selectedItemIndex < m_listCtrlPacketList.GetItemCount())
		{
			m_listCtrlPacketList.SetSelectionMark(--selectedItemIndex);
			selectedItemChangedFlag = true;
		}
	}
	break;
	case VK_DOWN:
	{
		if (selectedItemIndex >= 0 && selectedItemIndex < m_listCtrlPacketList.GetItemCount() - 1)
		{
			m_listCtrlPacketList.SetSelectionMark(++selectedItemIndex);
			selectedItemChangedFlag = true;
		}
	}
	break;
	default:
		break;
	}

	/* ѡ���з��ͱ仯����ӡ���ݰ���Ϣ���ֽ��� */
	if (selectedItemChangedFlag)
	{
		CString strPktNum = m_listCtrlPacketList.GetItemText(selectedItemIndex, 0);
		int pktNum = _ttoi(strPktNum);
		if (pktNum < 1 || pktNum > m_pool.getSize())
		{
			return;
		}
		// POSITION pos = g_packetLinkList.FindIndex(pktNum - 1);
		// Packet &pkt = g_packetLinkList.GetAt(pos);
		const Packet &pkt = m_pool.get(pktNum);
		printTreeCtrlPacketDetails(pkt);
		printEditCtrlPacketBytes(pkt);
	}

	*pResult = 0;
}
void translateNameInDNS(char *name1, const char *name2)
{
	strcpy_s(name1, 256, name2);

	char *p = name1;
	bool canMove = false;

	if (!isalnum(*p) && *p != '-')
	{
		canMove = true;
	}

	/* ������ת��Ϊ'.' */
	while (*p)
	{
		if (!isalnum(*p) && *p != '-')
		{
			*p = '.';
		}
		++p;
	}

	/* ������������ǰ��1λ */
	if (canMove)
	{
		p = name1;
		while (*p)
		{
			*p = *(p + 1);
			++p;
		}
	}
}
CString translateNameInDNS(const char *name)
{
	CString strName(name);
	bool canMove = false;

	if (!isalnum(strName.GetAt(0)) && strName.GetAt(0) != '-')
	{
		canMove = true;
	}
	/* ������ת��Ϊ'.' */
	for (int i = 0; i < strName.GetLength(); ++i)
	{
		if (!isalnum(strName.GetAt(i)) && strName.GetAt(i) != '-')
		{
			strName.SetAt(i, '.');
		}
	}

	/* ������������ǰ��1λ */
	if (canMove)
	{
		for (int i = 0; i < strName.GetLength(); ++i)
		{
			strName.SetAt(i, strName.GetAt(i + 1));
		}
	}
	return strName;
}
/* DNS��Դ��¼���ݲ���ת�� ������ָ��0xc0��data2ת��Ϊ����ָ���data1 offsetΪ��dns�ײ���ƫ����*/
void translateData(const DNS_Header *dnsh, char *data1, char *data2, const int data2_len)
{
	char *p = data2;
	int count = 0, i = 0;

	/* ����data2 */
	while (count < data2_len)
	{
		/* ָ�� */
		if (*(u_char *)p == 0xC0)
		{
			++p;

			/* ��ȡָ����ָ������� */
			char *data_ptr = (char *)((u_char *)dnsh + *(u_char *)p);

			int pos = is0xC0PointerInName(data_ptr);
			if (pos)
			{
				translateData(dnsh, data1 + i, data_ptr, pos + 2);
			}
			else
			{
				strcpy_s(data1 + i, 256, data_ptr);
				i += strlen(data_ptr) + 1;
			}
			count += 2;
		}
		else
		{
			data1[i++] = *p;
			++p;
			++count;
		}
	}
}
CString getNameInDNS(char *name, const DNS_Header *pDNSHeader)
{
	int pointerPos;

	// name����0xC0ָ��
	if ((pointerPos = is0xC0PointerInName(name)) == -1)
	{
		return translateNameInDNS(name);
	}
	else
	{
		int valueOffset = *(name + pointerPos + 1);
		CString value = get0xC0PointerValue(pDNSHeader, valueOffset);

		char *pName = (char *)malloc(pointerPos);
		if (pName != nullptr && name != nullptr)
		{
			memcpy(pName, name, pointerPos);
		}
		else
		{
			AfxMessageBox(_T("pName or name is null. Cannot perform memcpy."), MB_OK | MB_ICONERROR);
		}
		CString strName(pName);
		strName += value;

		free(pName);
		return strName;
	}
}

int is0xC0PointerInName(char *name)
{
	if (name == NULL)
	{
		return -2;
	}
	char *p = name;
	int pos = 0;

	while (*p)
	{
		if (*(u_char *)p == 0xC0)
		{
			return pos;
		}
		++p;
		++pos;
	}
	return -1;
}
CString get0xC0PointerValue(const DNS_Header *pDNSHeader, const int offset)
{
	char *pValue = (char *)pDNSHeader + offset;
	CString strValue = getNameInDNS(pValue, pDNSHeader);
	return strValue;
}
void CSnifferUIDlg::OnMenuFileOpen()
{
	CFileDialog dlgFile(TRUE, _T(".pcap"), NULL, OFN_FILEMUSTEXIST | OFN_HIDEREADONLY, _T("pcap�ļ� (*.pcap)|*.pcap|�����ļ� (*.*)|*.*||"), NULL);
	if (dlgFile.DoModal() == IDOK)
	{
		CString openFilePath = dlgFile.GetPathName();
		CString openFileName = dlgFile.GetFileName();
		if (dlgFile.GetFileExt() != "pcap") // ����ļ���չ��
		{
			AfxMessageBox("�޷����ļ�" + openFileName + "�������ļ���չ��");
			return;
		}
		if (openFileName == m_openFileName) // ����ļ����������ظ���
		{
			AfxMessageBox("�����ظ�����ͬ�ļ�" + openFileName);
			return;
		}
		if (m_catcher.openAdapter(openFilePath))
		{
			m_openFileName = openFileName;													// �����ļ���
			AfxGetMainWnd()->SetWindowText(openFileName);						// �޸ı�����Ϊ�ļ���
			m_menu.EnableMenuItem(ID_MENU_FILE_OPEN, MF_ENABLED);		// ���ò˵���"��"
			m_menu.EnableMenuItem(ID_MENU_FILE_CLOSE, MF_ENABLED);	// ���ò˵���"�ر�"
			m_menu.EnableMenuItem(ID_MENU_FILE_SAVEAS, MF_ENABLED); // ���ò˵���"���Ϊ"

			m_toolBarMain.GetToolBarCtrl().EnableButton(ID_MENU_FILE_OPEN, TRUE);		// ���ù�������ť"��"
			m_toolBarMain.GetToolBarCtrl().EnableButton(ID_MENU_FILE_SAVEAS, TRUE); // ���ù�������ť"���Ϊ"

			m_listCtrlPacketList.DeleteAllItems();
			m_treeCtrlPacketDetails.DeleteAllItems();
			m_editCtrlPacketBytes.SetWindowText(_T(""));
			m_pool.clear();

			m_pktDumper.setPath(openFilePath);
			m_catcher.startCapture(MODE_CAPTURE_OFFLINE);
			m_fileOpenFlag = true;

			CString status = "�Ѵ��ļ���" + openFileName;
			updateStatusBar(status, -1, -1);
			// m_statusBar.SetPaneText(0, status, true);		// �޸�״̬��
		}
	}
}
void CSnifferUIDlg::OnMenuFileClose()
{
	if (m_fileOpenFlag)
	{
		AfxGetMainWnd()->SetWindowText(_T("SnifferUI"));			 // �޸ı�����
		m_menu.EnableMenuItem(ID_MENU_FILE_OPEN, MF_ENABLED);	 // ���ò˵���"��"
		m_menu.EnableMenuItem(ID_MENU_FILE_CLOSE, MF_GRAYED);	 // ���ò˵���"�ر�"
		m_menu.EnableMenuItem(ID_MENU_FILE_SAVEAS, MF_GRAYED); // ���ò˵���"���Ϊ"

		m_toolBarMain.GetToolBarCtrl().EnableButton(ID_MENU_FILE_OPEN, TRUE);		 // ���ù�������ť"��"
		m_toolBarMain.GetToolBarCtrl().EnableButton(ID_MENU_FILE_SAVEAS, FALSE); // ���ù�������ť"���Ϊ"

		m_listCtrlPacketList.DeleteAllItems();
		m_treeCtrlPacketDetails.DeleteAllItems();
		m_editCtrlPacketBytes.SetWindowText(_T(""));
		m_pool.clear();

		m_openFileName = "";
		updateStatusBar(CString("����"), 0, 0);
	}
}
void CSnifferUIDlg::OnMenuFileSaveAs()
{
	CString saveAsFilePath = _T("");
	CString dumpFilePath = m_pktDumper.getPath();
	CString defaultFileName = m_pktDumper.getPath();
	CFileDialog dlgFile(FALSE, _T(".pcap"), defaultFileName, OFN_OVERWRITEPROMPT, _T("pcap�ļ� (*.pcap)|*.pcap|�����ļ� (*.*)|*.*||"), NULL);

	if (dlgFile.DoModal() == IDOK)
	{
		saveAsFilePath = dlgFile.GetPathName();
		m_pktDumper.dump(saveAsFilePath);
		AfxGetMainWnd()->SetWindowText(dlgFile.GetFileName());
		m_statusBar.SetPaneText(0, "�ѱ�������" + saveAsFilePath, true);
	}
}
void CSnifferUIDlg::OnMenuFileClearCache()
{
	if (clearDirectory(".\\tmp\\"))
	{
		updateStatusBar("�����ļ������", -1, -1);
	}
	else
	{
		updateStatusBar("�޻����ļ�������", -1, -1);
	}
}

void CSnifferUIDlg::OnMenuFileExit()
{
	exit(0);
}

void CSnifferUIDlg::OnTvnSelchangedTree1(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMTREEVIEW pNMTreeView = reinterpret_cast<LPNMTREEVIEW>(pNMHDR);
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	*pResult = 0;
}
BOOL CSnifferUIDlg::PreTranslateMessage(MSG* pMsg)
{
    if (m_hAccelMenu && ::TranslateAccelerator(m_hWnd, m_hAccelMenu, pMsg)) 
        return TRUE;
    
    if (m_hAccel && ::TranslateAccelerator(m_hWnd, m_hAccel, pMsg))
        return TRUE;
        
    return CDialog::PreTranslateMessage(pMsg);
}
void CSnifferUIDlg::OnLvnItemchangedList1(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	*pResult = 0;
}
