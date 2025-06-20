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
CTreeCtrl m_treeTrafficStats; // 全局变量定义

// 构造函数：初始化对话框资源及关键成员变量
CSnifferUIDlg::CSnifferUIDlg(CWnd *pParent /*=NULL*/)
	: CDialog(CSnifferUIDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME); // 加载主窗口图标
	m_catcher.setPool(&m_pool); // 初始化数据包捕获器，关联数据包池
	// m_dumper.setPool(&m_pool);		// 初始化数据包转储器（注释未启用）

	/* 状态标志初始化 */
	m_pktCaptureFlag = false; // 数据包捕获状态标志（初始未捕获）
	m_fileOpenFlag = false;   // 文件打开状态标志（初始未打开）
}

// 数据交换函数：关联对话框控件与成员变量
void CSnifferUIDlg::DoDataExchange(CDataExchange *pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, m_listCtrlPacketList);   // 关联数据包列表控件
	DDX_Control(pDX, IDC_TREE1, m_treeCtrlPacketDetails); // 关联数据包详情树形控件
	DDX_Control(pDX, IDC_EDIT1, m_editCtrlPacketBytes);   // 关联数据包字节流编辑控件
}

// 消息映射表：定义对话框消息与处理函数的关联
BEGIN_MESSAGE_MAP(CSnifferUIDlg, CDialog)
ON_WM_SYSCOMMAND()                  // 系统命令消息处理
ON_WM_PAINT()                       // 窗口绘制消息处理
ON_WM_QUERYDRAGICON()               // 拖动图标查询消息处理
ON_NOTIFY(NM_CLICK, IDC_LIST1, OnClickedList1) // 数据包列表点击事件处理

ON_NOTIFY(NM_CUSTOMDRAW, IDC_LIST1, &CSnifferUIDlg::OnCustomdrawList1) // 列表自定义绘制事件处理
ON_MESSAGE(WM_PKTCATCH, &CSnifferUIDlg::OnPktCatchMessage) // 自定义数据包捕获消息处理
ON_MESSAGE(WM_TEXIT, &CSnifferUIDlg::OnTExitMessage) // 自定义线程退出消息处理
ON_NOTIFY(LVN_KEYDOWN, IDC_LIST1, &CSnifferUIDlg::OnKeydownList1) // 列表按键事件处理
ON_COMMAND(ID_MENU_FILE_OPEN, &CSnifferUIDlg::OnMenuFileOpen) // 菜单“打开”命令处理
ON_COMMAND(ID_MENU_FILE_CLOSE, &CSnifferUIDlg::OnMenuFileClose) // 菜单“关闭”命令处理
ON_COMMAND(ID_MENU_FILE_CLEAR_CACHE, &CSnifferUIDlg::OnMenuFileClearCache) // 菜单“清空缓存”命令处理
ON_COMMAND(ID_MENU_FILE_SAVEAS, &CSnifferUIDlg::OnMenuFileSaveAs) // 菜单“另存为”命令处理
ON_COMMAND(ID_MENU_FILE_EXIT, &CSnifferUIDlg::OnMenuFileExit) // 菜单"退出"命令处理
ON_NOTIFY_EX(TTN_NEEDTEXT, 0, OnToolTipText) // 工具提示文本需求事件处理
ON_COMMAND(ID_TOOLBARBTN_START, &CSnifferUIDlg::OnClickedStart) // 工具栏“开始”按钮点击处理
ON_COMMAND(ID_TOOLBARBTN_STOP, &CSnifferUIDlg::OnClickedStop) // 工具栏“停止”按钮点击处理
ON_COMMAND(ID_TOOLBARBTN_CLEAR, &CSnifferUIDlg::OnClickedClear) // 工具栏“清空”按钮点击处理
ON_COMMAND(ID_TOOLBARBTN_FILTER, &CSnifferUIDlg::OnClickedFilter) // 工具栏“过滤”按钮点击处理
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
	initialAccelerator();						// 快捷键初始化
	initialMenuBar();								// 菜单栏初始化
	initialToolBar();								// 工具栏初始化
	initialComboBoxDevList();				// 网卡列表初始化
	initialComboBoxFilterList();		// 过滤器列表初始化
	initialListCtrlPacketList();		// 列表控件（数据包列表）初始化
	initialTreeCtrlPacketDetails(); // 树形控件（数据包详情）初始化
	initialEditCtrlPacketBytes();		// 编辑控件（数据包字节流）初始化
	initialStatusBar();							// 状态栏初始化
	createDirectory(".\\tmp");			// 判断tmp文件夹是否存在，不存在则创建
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

        // 获取两个工具栏高度
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

        // 调整客户区起始位置
        rcClient.top += mainToolbarHeight + filterToolbarHeight + 10;

        // 计算控件区域（保留状态栏空间）
        int statusBarHeight = 20;
        int listHeight = rcClient.Height() * 2 / 5;
        int remainingHeight = rcClient.Height() - listHeight - statusBarHeight - 15;

        // 更新主控件布局
        m_listCtrlPacketList.MoveWindow(rcClient.left, rcClient.top, rcClient.Width(), listHeight);
        m_treeCtrlPacketDetails.MoveWindow(rcClient.left, 
            rcClient.top + listHeight + 5, 
            rcClient.Width() / 2 - 3, 
            remainingHeight);
        m_editCtrlPacketBytes.MoveWindow(rcClient.left + rcClient.Width() / 2 + 3, 
            rcClient.top + listHeight + 5, 
            rcClient.Width() / 2 - 3, 
            remainingHeight);

        // 更新工具栏位置
        if (m_toolBarMain.GetSafeHwnd()) {
            m_toolBarMain.MoveWindow(5, 5, rcClient.Width() - 10, mainToolbarHeight);
        }
        if (m_toolBarFilter.GetSafeHwnd()) {
            m_toolBarFilter.MoveWindow(5, 5 + mainToolbarHeight + 5, rcClient.Width() - 10, filterToolbarHeight);
        }

        // 更新状态栏位置
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
	// 获取当前时间
	time_t tt = time(NULL);
	struct tm tm_now;
	localtime_s(&tm_now, &tt);
	CTime currentTime(tm_now.tm_year + 1900, tm_now.tm_mon + 1, tm_now.tm_mday,
										tm_now.tm_hour, tm_now.tm_min, tm_now.tm_sec);

	/* 若没有选中网卡，报提示信息；否则，创建线程抓包 */
	int selItemIndex = m_comboBoxDevList.GetCurSel();
	if (selItemIndex <= 0)
	{
		AfxMessageBox(_T("请选择网卡"), MB_OK);
		return;
	}

	if (m_catcher.openAdapter(selItemIndex, currentTime))
	{
		CString status = "正在捕获：" + m_catcher.getDevName();
		/* 修改控件使能状态 */
		m_comboBoxDevList.EnableWindow(FALSE);
		m_toolBarMain.GetToolBarCtrl().EnableButton(ID_TOOLBARBTN_START, FALSE);
		m_toolBarMain.GetToolBarCtrl().EnableButton(ID_TOOLBARBTN_STOP, TRUE);

		m_toolBarMain.GetToolBarCtrl().EnableButton(ID_MENU_FILE_OPEN, FALSE);
		m_toolBarMain.GetToolBarCtrl().EnableButton(ID_MENU_FILE_SAVEAS, FALSE);

		m_menu.EnableMenuItem(ID_MENU_FILE_OPEN, MF_GRAYED);	// 禁用菜单项"打开"
		m_menu.EnableMenuItem(ID_MENU_FILE_CLOSE, MF_GRAYED); // 禁用菜单项"关闭"
		m_menu.EnableMenuItem(ID_MENU_FILE_OPEN, MF_GRAYED);	// 禁用菜单项"另存为"

		/* 清空控件显示内容 */
		m_listCtrlPacketList.DeleteAllItems();
		m_treeCtrlPacketDetails.DeleteAllItems();
		m_editCtrlPacketBytes.SetWindowText(_T(""));

		AfxGetMainWnd()->SetWindowText(status);

		/* 清空内存中数据包池 */
		m_pool.clear();

		/* 更新状态栏 */
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
	CString status = "捕获结束：" + m_catcher.getDevName();
	AfxGetMainWnd()->SetWindowText(m_pktDumper.getPath()); // 修改标题栏

	m_comboBoxDevList.EnableWindow(TRUE);
	m_toolBarMain.GetToolBarCtrl().EnableButton(ID_TOOLBARBTN_START, TRUE);
	m_toolBarMain.GetToolBarCtrl().EnableButton(ID_TOOLBARBTN_STOP, FALSE);
	m_toolBarMain.GetToolBarCtrl().EnableButton(ID_MENU_FILE_OPEN, TRUE);
	m_toolBarMain.GetToolBarCtrl().EnableButton(ID_MENU_FILE_SAVEAS, TRUE);

	m_menu.EnableMenuItem(ID_MENU_FILE_OPEN, MF_ENABLED);		// 启用菜单项"打开"
	m_menu.EnableMenuItem(ID_MENU_FILE_CLOSE, MF_GRAYED);		// 禁用菜单项"关闭"
	m_menu.EnableMenuItem(ID_MENU_FILE_SAVEAS, MF_ENABLED); // 启用菜单项"另存为"
	m_statusBar.SetPaneText(0, status, true);								// 修改状态

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

	/* 菜单项禁用 */
	//	CMenu* pMenu = this->GetMenu();
	if (m_menu)
	{
		m_menu.EnableMenuItem(ID_MENU_FILE_CLOSE, MF_GRAYED);	 // 禁用菜单项"关闭"
		m_menu.EnableMenuItem(ID_MENU_FILE_SAVEAS, MF_GRAYED); // 禁用菜单项"另存为"
	}
}

void CSnifferUIDlg::initialToolBar()
{
	// 主工具栏创建
	if (!m_toolBarMain.CreateEx(this, TBSTYLE_FLAT, WS_CHILD | WS_VISIBLE | CBRS_TOP | CBRS_TOOLTIPS | CBRS_GRIPPER | CBRS_FLYBY | CBRS_SIZE_DYNAMIC) ||
			!m_toolBarMain.LoadToolBar(IDR_TOOLBAR1))
	{
		AfxMessageBox(_T("未能创建主工具栏\n"));
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

	// 读取主工具栏按钮图标，存储到ImageList，工具栏读取ImageList
	m_imageListMain.Create(BITMAP_WIDTH, BITMAP_HEIGHT, ILC_COLOR24 | ILC_MASK, 0, 0);
	for (int i = 0; i < BITMAP_LIST_MAIN_SIZE; ++i)
	{
		m_bitmapListMain[i].LoadBitmapA(IDB_BITMAP_DEV + i);
		m_imageListMain.Add(&m_bitmapListMain[i], RGB(0, 0, 0));
	}
	m_toolBarMain.GetToolBarCtrl().SetImageList(&m_imageListMain);

	// 禁用主工具栏上的按钮
	m_toolBarMain.GetToolBarCtrl().EnableButton(ID_TOOLBARBTN_STOP, FALSE);
	m_toolBarMain.GetToolBarCtrl().EnableButton(ID_MENU_FILE_SAVEAS, FALSE);

	// 过滤器工具栏创建
	if (!m_toolBarFilter.CreateEx(this, TBSTYLE_FLAT, WS_CHILD | WS_VISIBLE | CBRS_TOP | CBRS_TOOLTIPS | CBRS_GRIPPER | CBRS_FLYBY | CBRS_SIZE_DYNAMIC) ||
			!m_toolBarFilter.LoadToolBar(IDR_TOOLBAR2))
	{
		AfxMessageBox(_T("未能创建过滤器工具栏\n"));
		return;
	}

	// 在过滤器工具栏按钮上创建组合框（过滤器列表）
	index = m_toolBarFilter.CommandToIndex(ID_TOOLBARBTN_FILTERLIST);
	m_toolBarFilter.SetButtonInfo(index, ID_TOOLBARBTN_FILTERLIST, TBBS_SEPARATOR, 300); // 设置组合框的ID，类型（这里是分隔栏），300是指分隔栏宽度

	// 根据分隔符的尺寸rect建立组合框
	m_toolBarFilter.GetItemRect(index, &rect);
	rect.top += 3;
	rect.bottom += 200;  // 增加下拉区域高度
	rect.left += 10;
	m_comboBoxFilterList.Create(WS_CHILD | WS_VISIBLE | WS_VSCROLL | CBS_DROPDOWNLIST, rect, &m_toolBarFilter, ID_TOOLBARBTN_FILTERLIST);

	// 读取过滤器工具栏按钮图标，存储到ImageList，工具栏读取ImageList
	m_imageListFilter.Create(BITMAP_WIDTH, BITMAP_HEIGHT, ILC_COLOR24 | ILC_MASK, 0, 0);
	for (int i = 0; i < BITMAP_LIST_FILTER_SIZE; ++i)
	{
		m_bitmapListFilter[i].LoadBitmapA(IDB_BITMAP_DEV + BITMAP_LIST_MAIN_SIZE + i);
		m_imageListFilter.Add(&m_bitmapListFilter[i], RGB(0, 0, 0));
	}
	m_toolBarFilter.GetToolBarCtrl().SetImageList(&m_imageListFilter);

	// 设置下拉列表字体
	m_comboFont.CreateFontA(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, 0, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_ROMAN, "新宋体");
	m_comboBoxDevList.SetFont(&m_comboFont);
	m_comboBoxFilterList.SetFont(&m_comboFont);

	// 设置下拉列表高度
	m_comboBoxDevList.SetItemHeight(-1, 18);
	m_comboBoxFilterList.SetItemHeight(-1, 18);

	// 控件条定位
	RepositionBars(AFX_IDW_CONTROLBAR_FIRST, AFX_IDW_CONTROLBAR_LAST, 0);
}
void CSnifferUIDlg::initialComboBoxDevList()
{
	m_comboBoxDevList.AddString("选择网卡");
	m_comboBoxDevList.SetCurSel(0);

	pcap_if_t* dev = NULL;
	pcap_if_t* allDevs = NULL;
	char errbuf[PCAP_ERRBUF_SIZE + 1];
	if (pcap_findalldevs(&allDevs, errbuf) == -1)
	{
		AfxMessageBox(_T("pcap_findalldevs错误!"), MB_OK);
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

	m_comboBoxFilterList.AddString("选择过滤器（可选）");
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

	DWORD dwStyle = m_listCtrlPacketList.GetExtendedStyle(); // 添加列表控件的网格线
	dwStyle |= LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_HEADERDRAGDROP;
	m_listCtrlPacketList.SetExtendedStyle(dwStyle);

	m_listCtrlPacketList.GetWindowRect(&rect);
	ScreenToClient(&rect);

	int index = 0;
	m_listCtrlPacketList.InsertColumn(index, "编号", LVCFMT_CENTER, rect.Width() * 0.05);
	m_listCtrlPacketList.InsertColumn(++index, "时间", LVCFMT_CENTER, rect.Width() * 0.15);
	m_listCtrlPacketList.InsertColumn(++index, "协议", LVCFMT_CENTER, rect.Width() * 0.05);
	m_listCtrlPacketList.InsertColumn(++index, "长度", LVCFMT_CENTER, rect.Width() * 0.05);
	m_listCtrlPacketList.InsertColumn(++index, "源MAC地址", LVCFMT_CENTER, rect.Width() * 0.175);
	m_listCtrlPacketList.InsertColumn(++index, "目的MAC地址", LVCFMT_CENTER, rect.Width() * 0.175);
	m_listCtrlPacketList.InsertColumn(++index, "源IP地址", LVCFMT_CENTER, rect.Width() * 0.175);
	m_listCtrlPacketList.InsertColumn(++index, "目的IP地址", LVCFMT_CENTER, rect.Width() * 0.175);

}

void CSnifferUIDlg::initialTreeCtrlPacketDetails()
{
	// 根据列表控件（数据包列表）位置调整树形控件（数据包详情）位置
	CRect rect, winRect;
	m_listCtrlPacketList.GetWindowRect(&rect);
	ScreenToClient(&rect);
	GetDlgItem(IDC_TREE1)->SetWindowPos(NULL, rect.left, rect.bottom + 5, rect.Width() * 0.5, rect.Height() + 125, SWP_NOZORDER);
}

void CSnifferUIDlg::initialEditCtrlPacketBytes()
{
	// 根据树形控件控件（数据包详情）位置调整编辑控件（数据包字节流）位置
	CRect rect;
	m_treeCtrlPacketDetails.GetWindowRect(&rect);
	ScreenToClient(&rect);
	GetDlgItem(IDC_EDIT1)->SetWindowPos(NULL, rect.right + 5, rect.top, rect.Width(), rect.Height(), SWP_NOZORDER);
}

void CSnifferUIDlg::initialStatusBar()
{
	if (m_statusBar.Create(this)) // 创建菜单栏
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
		RepositionBars(AFX_IDW_CONTROLBAR_FIRST, AFX_IDW_CONTROLBAR_LAST, 0); // 显示状态栏
	}
}
/**
 *	@brief	更新状态栏
 *	@param [in]	status	状态
 *	@param [in]	pktTotalNum	数据包总数	值为非负数时更新该字段
 *	@param [in]	pktDisplayNum	数据包显示个数	值为非负数时更新该字段
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
		text.Format("数据包：%d", pktTotalNum);
		m_statusBar.SetPaneText(index, text, TRUE);
	}
	if (pktDisplayNum >= 0)
	{
		int index = m_statusBar.CommandToIndex(ID_INDICATOR_PKT_DISPLAY_NUM);
		CString text;
		double percentage = (pktDisplayNum == 0 || pktTotalNum == 0) ? 0.0 : ((double)pktDisplayNum / pktTotalNum * 100);
		text.Format("已显示：%d (%.1f%%)", pktDisplayNum, percentage);
		m_statusBar.SetPaneText(index, text, TRUE);
	}
}

/**
 *	@brief	在指定路径上创建文件夹
 *	@param [in]	dirPath	 文件夹路径
 *	@return	true 创建成功 false 创建失败（文件夹已存在）
 */
bool CSnifferUIDlg::createDirectory(const CString &dirPath)
{
	if (!PathIsDirectory(dirPath.GetString())) // 是否有重名文件夹
	{
		::CreateDirectory(dirPath.GetString(), 0);
		return true;
	}
	return false;
}

/**
 *	@brief	清空指定文件夹中所有文件
 *	@param [in]	dirPath	 文件夹路径
 *	@return	true 清空成功 false 清空失败
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

		// 跳过 . 和 .. ; 否则会陷入无限循环中
		if (finder.IsDots())
			continue;

		// 如果是目录，进入搜索 （递归）
		if (finder.IsDirectory())
		{
			CString subDirPath = dirPath + finder.GetFileName();
			clearDirectory(subDirPath);	 // 删除文件夹下的文件
			RemoveDirectory(subDirPath); // 移除空文件
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
 *	@brief	打印数据包概要信息到列表控件
 *	@param	数据包
 *	@return	0 打印成功	-1 打印失败
 */
int CSnifferUIDlg::printListCtrlPacketList(const Packet &pkt)
{
	if (pkt.isEmpty())
		return -1;

	int row = 0; // 行号
	int col = 0; // 列号
	/* 打印编号 */
	CString strNum;
	strNum.Format("%d", pkt.num);

	UINT mask = LVIF_PARAM | LVIF_TEXT;

	// protocol字段在OnCustomdrawList1()中使用
	row = m_listCtrlPacketList.InsertItem(mask, m_listCtrlPacketList.GetItemCount(), strNum, 0, 0, 0, (LPARAM) & (pkt.protocol));

	/* 打印时间 */
	CTime pktArrivalTime((time_t)(pkt.header->ts.tv_sec));
	CString strPktArrivalTime = pktArrivalTime.Format("%Y/%m/%d %H:%M:%S");
	m_listCtrlPacketList.SetItemText(row, ++col, strPktArrivalTime);

	/* 打印协议 */
	if (!pkt.protocol.IsEmpty())
		m_listCtrlPacketList.SetItemText(row, ++col, pkt.protocol);
	else
		++col;

	/* 打印长度 */
	CString strCaplen;
	strCaplen.Format("%d", pkt.header->caplen);
	m_listCtrlPacketList.SetItemText(row, ++col, strCaplen);

	/* 打印源目MAC地址 */
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

	/* 打印源目IP地址 */
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
 *	@brief	打印数据包概要信息到列表控件
 *	@param	pool 数据包池
 *	@return	>=0 数据包池中数据包个数 -1 打印失败
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
 *	@brief	遍历数据包链表，根据过滤器名称打印数据包到列表控件
 *	@param	packetLinkList	数据包链表
 *	@param	filter	过滤器名称
 *	@return	>=0 过滤出的数据包个数	-1 打印失败
 */
int CSnifferUIDlg::printListCtrlPacketList(PacketPool &pool, const CString &filter)
{
	if (pool.isEmpty() || filter.IsEmpty())
		return -1;

	int pktNum = pool.getSize();
	int filterPktNum = 0;
	for (int i = 0; i < pktNum; ++i)
	{
		const Packet &pkt = pool.get(i); // BUG：可能有
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
		/* 若当前字节是行首，打印行首偏移量 */
		if (byteCount % 16 == 0)
		{
			strTmp.Format("%04X:", offset);
			strPacketBytes += strTmp + " ";
		}

		/* 打印16进制字节 */
		strTmp.Format("%02X", *pHexPacketBytes);
		strPacketBytes += strTmp + " ";
		++pHexPacketBytes;
		++byteCount16;

		switch (byteCount16)
		{
		case 8:
		{
			/* 每读取8个字节打印一个制表符 */
			strPacketBytes += "\t";
			// strPacketBytes += "#";
		}
		break;
		case 16:
		{
			/* 每读取16个字节打印对应字节的ASCII字符，只打印字母数字 */
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
	/* 若数据包总长度不是16字节对齐时，打印最后一行字节对应的ASCII字符 */
	if (pkt.header->caplen % 16 != 0)
	{
		/* 空格填充，保证字节流16字节对齐 */
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
		/* 打印最后一行字节对应的ASCII字符 */
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

	/* 建立编号结点 */
	CString strText;

	CTime pktArrivalTime((time_t)(pkt.header->ts.tv_sec));
	CString strPktArrivalTime = pktArrivalTime.Format("%Y/%m/%d %H:%M:%S");

	strText.Format("第%d个数据包（%s, 共 %hu 字节, 捕获 %hu 字节）", pkt.num, strPktArrivalTime, pkt.header->len, pkt.header->caplen);

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
	/* 获取源目MAC地址 */
	CString strSrcMAC = MACAddr2CString(pkt.ethh->srcaddr);
	CString strDstMAC = MACAddr2CString(pkt.ethh->dstaddr);
	CString strEthType;
	strEthType.Format("0x%04X", ntohs(pkt.ethh->eth_type));

	HTREEITEM EthNode = m_treeCtrlPacketDetails.InsertItem("以太网（" + strSrcMAC + " -> " + strDstMAC + "）", parentNode, 0);

	m_treeCtrlPacketDetails.InsertItem("目的MAC地址：" + strDstMAC, EthNode, 0);
	m_treeCtrlPacketDetails.InsertItem("源MAC地址：" + strSrcMAC, EthNode, 0);
	m_treeCtrlPacketDetails.InsertItem("类型：" + strEthType, EthNode, 0);

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

	HTREEITEM IPNode = m_treeCtrlPacketDetails.InsertItem("IP（" + IPAddr2CString(pkt.iph->srcaddr) + " -> " + IPAddr2CString(pkt.iph->dstaddr) + "）", parentNode, 0);
	CString strText;

	strText.Format("版本号：%d", pkt.iph->ver_headerlen >> 4);
	m_treeCtrlPacketDetails.InsertItem(strText, IPNode, 0);

	strText.Format("首部长度：%d 字节（%d）", pkt.getIPHeaderLegnth(), pkt.getIPHeaderLengthRaw());
	m_treeCtrlPacketDetails.InsertItem(strText, IPNode, 0);

	strText.Format("服务质量：0x%02X", pkt.iph->tos);
	m_treeCtrlPacketDetails.InsertItem(strText, IPNode, 0);

	strText.Format("总长度：%hu", ntohs(pkt.iph->totallen));
	m_treeCtrlPacketDetails.InsertItem(strText, IPNode, 0);

	strText.Format("标识：0x%04hX（%hu）", ntohs(pkt.iph->identifier), ntohs(pkt.iph->identifier));
	m_treeCtrlPacketDetails.InsertItem(strText, IPNode, 0);

	strText.Format("标志：0x%02X", pkt.getIPFlags());
	HTREEITEM IPFlagNode = m_treeCtrlPacketDetails.InsertItem(strText, IPNode, 0);

	strText = "RSV：0";
	m_treeCtrlPacketDetails.InsertItem(strText, IPFlagNode, 0);

	strText.Format("DF：%d", pkt.getIPFlagDF());
	m_treeCtrlPacketDetails.InsertItem(strText, IPFlagNode, 0);

	strText.Format("MF：%d", pkt.getIPFlagsMF());
	m_treeCtrlPacketDetails.InsertItem(strText, IPFlagNode, 0);

	strText.Format("片偏移：%d", pkt.getIPOffset());
	m_treeCtrlPacketDetails.InsertItem(strText, IPNode, 0);

	strText.Format("TTL：%u", pkt.iph->ttl);
	m_treeCtrlPacketDetails.InsertItem(strText, IPNode, 0);

	switch (pkt.iph->protocol)
	{
	case PROTOCOL_ICMP:
		strText = "协议：ICMP（1）";
		break;
	case PROTOCOL_TCP:
		strText = "协议：TCP（6）";
		break;
	case PROTOCOL_UDP:
		strText = "协议：UDP（17）";
		break;
	default:
		strText.Format("协议：未知（%d）", pkt.iph->protocol);
		break;
	}
	m_treeCtrlPacketDetails.InsertItem(strText, IPNode, 0);

	strText.Format("校验和：0x%02hX", ntohs(pkt.iph->checksum));
	m_treeCtrlPacketDetails.InsertItem(strText, IPNode, 0);

	strText = "源IP地址：" + IPAddr2CString(pkt.iph->srcaddr);
	m_treeCtrlPacketDetails.InsertItem(strText, IPNode, 0);

	strText = "目的IP地址：" + IPAddr2CString(pkt.iph->dstaddr);
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
		strText.Format("ARP（请求)");
		break;
	case ARP_OPCODE_REPLY:
		strText.Format("ARP（响应)");
		break;
	default:
		strText.Format("ARP");
		break;
	}
	ARPNode = m_treeCtrlPacketDetails.InsertItem(strText, 0, 0, parentNode, 0);

	strText.Format("硬件类型：%hu", ntohs(pkt.arph->hwtype));
	m_treeCtrlPacketDetails.InsertItem(strText, ARPNode, 0);

	strText.Format("协议类型：0x%04hx (%hu)", ntohs(pkt.arph->ptype), ntohs(pkt.arph->ptype));
	m_treeCtrlPacketDetails.InsertItem(strText, ARPNode, 0);

	strText.Format("硬件地址长度：%u", pkt.arph->hwlen);
	m_treeCtrlPacketDetails.InsertItem(strText, ARPNode, 0);

	strText.Format("协议地址长度：%u", pkt.arph->plen);
	m_treeCtrlPacketDetails.InsertItem(strText, ARPNode, 0);

	switch (ntohs(pkt.arph->opcode))
	{
	case ARP_OPCODE_REQUET:
		strText.Format("OP码：请求（%hu）", ntohs(pkt.arph->opcode));
		break;
	case ARP_OPCODE_REPLY:
		strText.Format("OP码：响应（%hu）", ntohs(pkt.arph->opcode));
		break;
	default:
		strText.Format("OP码：未知（%hu）", ntohs(pkt.arph->opcode));
		break;
	}
	m_treeCtrlPacketDetails.InsertItem(strText, ARPNode, 0);

	strText = "源MAC地址：" + MACAddr2CString(pkt.arph->srcmac);
	m_treeCtrlPacketDetails.InsertItem(strText, ARPNode, 0);

	strText = "源IP地址：" + IPAddr2CString(pkt.arph->srcip);
	m_treeCtrlPacketDetails.InsertItem(strText, ARPNode, 0);

	strText = "目的MAC地址：" + MACAddr2CString(pkt.arph->dstmac);
	m_treeCtrlPacketDetails.InsertItem(strText, ARPNode, 0);

	strText = "目的IP地址：" + IPAddr2CString(pkt.arph->dstip);
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
		strTmp = "（回应应答报告）";
		break;
	case ICMP_TYPE_DESTINATION_UNREACHABLE:
		strTmp = "（信宿不可达报告）";
		break;
	case ICMP_TYPE_SOURCE_QUENCH:
		strTmp = "（源端抑制报告）";
		break;
	case ICMP_TYPE_REDIRECT:
		strTmp = "（重定向报告）";
		break;
	case ICMP_TYPE_ECHO:
		strTmp = "（回应请求报告）";
		break;
	case ICMP_TYPE_ROUTER_ADVERTISEMENT:
		strTmp = "（路由器通告报告）";
		break;
	case ICMP_TYPE_ROUTER_SOLICITATION:
		strTmp = "（路由器询问报告）";
		break;
	case ICMP_TYPE_TIME_EXCEEDED:
		strTmp = "（超时报告）";
		break;
	case ICMP_TYPE_PARAMETER_PROBLEM:
		strTmp = "（数据报参数错误报告）";
		break;
	case ICMP_TYPE_TIMESTAMP:
		strTmp = "（时间戳请求报告）";
		break;
	case ICMP_TYPE_TIMESTAMP_REPLY:
		strTmp = "（时间戳响应报告）";
		break;
	default:
		strTmp.Format("（未知）");
		break;
	}
	strText += strTmp;
	ICMPNode = m_treeCtrlPacketDetails.InsertItem(strText, parentNode, 0);

	IP_Address addr = *(IP_Address *)&(pkt.icmph->others);
	u_short id = pkt.getICMPID();
	u_short seq = pkt.getICMPSeq();

	strText.Format("类型：%u", pkt.icmph->type);
	m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

	switch (pkt.icmph->type)
	{
	case ICMP_TYPE_ECHO_REPLY:
	{
		strText = "代码：0";
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		strText.Format("校验和:0x%04hX", ntohs(pkt.icmph->chksum));
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		strText.Format("标识：%hu", id);
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		strText.Format("序号：%hu", seq);
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		break;
	}

	case ICMP_TYPE_DESTINATION_UNREACHABLE:
		strText = "代码：";
		switch (pkt.icmph->code)
		{
		case ICMP_TYPE_DESTINATION_UNREACHABLE_CODE_NET_UNREACHABLE:
			strText.Format("网络不可达 （%d）", pkt.icmph->code);
			break;

		case ICMP_TYPE_DESTINATION_UNREACHABLE_CODE_HOST_UNREACHABLE:
			strText.Format("主机不可达 （%d）", pkt.icmph->code);
			break;

		case ICMP_TYPE_DESTINATION_UNREACHABLE_CODE_PROTOCOL_UNREACHABLE:
			strText.Format("协议不可达 （%d）", pkt.icmph->code);
			break;

		case ICMP_TYPE_DESTINATION_UNREACHABLE_CODE_PORT_UNREACHABLE:
			strText.Format("端口不可达 （%d）", pkt.icmph->code);
			break;

		case 6:
			strTmp = "信宿网络未知 （6）";
			break;

		case 7:
			strTmp = "信宿主机未知 （7）";
			break;

		default:
			strText.Format("未知 （%d）", pkt.icmph->code);
			break;
		}
		strText += strTmp;
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		strText.Format("校验和：0x%04hX", ntohs(pkt.icmph->chksum));
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);
		break;

	case ICMP_TYPE_SOURCE_QUENCH:
		strText.Format("代码：%d", ICMP_TYPE_SOURCE_QUENCH_CODE);
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		strText.Format("校验和：0x%04hX", ntohs(pkt.icmph->chksum));
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);
		break;

	case ICMP_TYPE_REDIRECT:
		strText = "代码：";
		switch (pkt.icmph->code)
		{
		case ICMP_TYPE_REDIRECT_CODE_REDIRECT_DATAGRAMS_FOR_THE_NETWORK:
			strText.Format("对特定网络重定向（%d)", pkt.icmph->code);
			break;

		case ICMP_TYPE_REDIRECT_CODE_REDIRECT_DATAGRAMS_FOR_THE_HOST:
			strText.Format("对特定主机重定向 （%d)", pkt.icmph->code);
			break;

		case ICMP_TYPE_REDIRECT_CODE_REDIRECT_DATAGRAMS_FOR_THE_TOS_AND_NETWORK:
			strText.Format("基于指定的服务类型对特定网络重定向 （%d）", pkt.icmph->code);
			break;

		case ICMP_TYPE_REDIRECT_CODE_REDIRECT_DATAGRAMS_FOR_THE_TOS_AND_HOST:
			strText.Format("基于指定的服务类型对特定主机重定向 （%d）", pkt.icmph->code);
			break;
		}
		strText += strTmp;
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		strText.Format("校验和：0x%04hx", ntohs(pkt.icmph->chksum));
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		strText = "目标路由器的IP地址：" + IPAddr2CString(addr);
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);
		break;

	case ICMP_TYPE_ECHO:
		strText.Format("代码：%d", pkt.icmph->code);
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		strText.Format("校验和：0x%04hX", ntohs(pkt.icmph->chksum));
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		strText.Format("标识：%hu", id);
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		strText.Format("序号：%hu", seq);
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);
		break;

	case ICMP_TYPE_TIME_EXCEEDED:
		strText = "代码：";
		switch (pkt.icmph->code)
		{
		case ICMP_TYPE_TIME_EXCEEDED_CODE_TTL_EXCEEDED_IN_TRANSIT:
			strText.Format("TTL超时 （%d）", pkt.icmph->code);
			break;
		case ICMP_TYPE_TIME_EXCEEDED_CODE_FRAGMENT_REASSEMBLY_TIME_EXCEEDE:
			strText.Format("分片重组超时 （%d）", pkt.icmph->code);
			break;
		}
		strText += strTmp;
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		strText.Format("校验和：0x%04hx", ntohs(pkt.icmph->chksum));
		m_treeCtrlPacketDetails.InsertItem(strText, ICMPNode, 0);

		break;

	default:
		strText.Format("代码：%d", pkt.icmph->code);
		m_treeCtrlPacketDetails.InsertItem(strText, 0, 0, ICMPNode, 0);

		strText.Format("校验和：0x%04hX", pkt.icmph->chksum);
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

	strText.Format("TCP（%hu -> %hu）", ntohs(pkt.tcph->srcport), ntohs(pkt.tcph->dstport));
	TCPNode = m_treeCtrlPacketDetails.InsertItem(strText, parentNode, 0);

	strText.Format("源端口：%hu", ntohs(pkt.tcph->srcport));
	m_treeCtrlPacketDetails.InsertItem(strText, TCPNode, 0);

	strText.Format("目的端口：%hu", ntohs(pkt.tcph->dstport));
	m_treeCtrlPacketDetails.InsertItem(strText, TCPNode, 0);

	strText.Format("序列号：0x%0lX", ntohl(pkt.tcph->seq));
	m_treeCtrlPacketDetails.InsertItem(strText, TCPNode, 0);

	strText.Format("确认号：0x%0lX", ntohl(pkt.tcph->ack));
	m_treeCtrlPacketDetails.InsertItem(strText, TCPNode, 0);

	strText.Format("首部长度：%d 字节（%d）", pkt.getTCPHeaderLength(), pkt.getTCPHeaderLengthRaw());
	m_treeCtrlPacketDetails.InsertItem(strText, TCPNode, 0);

	strText.Format("标志：0x%03X", pkt.getTCPFlags());
	HTREEITEM TCPFlagNode = m_treeCtrlPacketDetails.InsertItem(strText, TCPNode, 0);

	strText.Format("URG：%d", pkt.getTCPFlagsURG());
	m_treeCtrlPacketDetails.InsertItem(strText, TCPFlagNode, 0);

	strText.Format("ACK：%d", pkt.getTCPFlagsACK());
	m_treeCtrlPacketDetails.InsertItem(strText, TCPFlagNode, 0);

	strText.Format("PSH：%d", pkt.getTCPFlagsPSH());
	m_treeCtrlPacketDetails.InsertItem(strText, TCPFlagNode, 0);

	strText.Format("RST：%d", pkt.getTCPFlagsRST());
	m_treeCtrlPacketDetails.InsertItem(strText, TCPFlagNode, 0);

	strText.Format("SYN：%d", pkt.getTCPFlagsSYN());
	m_treeCtrlPacketDetails.InsertItem(strText, TCPFlagNode, 0);

	strText.Format("FIN：%d", pkt.getTCPFlagsFIN());
	m_treeCtrlPacketDetails.InsertItem(strText, TCPFlagNode, 0);

	strText.Format("窗口大小：%hu", ntohs(pkt.tcph->win_size));
	m_treeCtrlPacketDetails.InsertItem(strText, TCPNode, 0);

	strText.Format("校验和：0x%04hX", ntohs(pkt.tcph->chksum));
	m_treeCtrlPacketDetails.InsertItem(strText, TCPNode, 0);

	strText.Format("紧急指针：%hu", ntohs(pkt.tcph->urg_ptr));
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

	strText.Format("UDP（%hu -> %hu）", ntohs(pkt.udph->srcport), ntohs(pkt.udph->dstport));
	UDPNode = m_treeCtrlPacketDetails.InsertItem(strText, parentNode, 0);

	strText.Format("源端口：%hu", ntohs(pkt.udph->srcport));
	m_treeCtrlPacketDetails.InsertItem(strText, UDPNode, 0);

	strText.Format("目的端口：%hu", ntohs(pkt.udph->dstport));
	m_treeCtrlPacketDetails.InsertItem(strText, UDPNode, 0);

	strText.Format("长度：%hu", ntohs(pkt.udph->len));
	m_treeCtrlPacketDetails.InsertItem(strText, UDPNode, 0);

	strText.Format("校验和：0x%04hX", ntohs(pkt.udph->checksum));
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
		strText = "DNS（请求）";
		break;
	case DNS_FLAGS_QR_REPLY:
		strText = "DNS（响应）";
		break;
	}
	return m_treeCtrlPacketDetails.InsertItem(strText, parentNode, 0);
}

	/**
	 * @brief 打印DNS头部信息到树形控件
	 * @param [in] pkt 数据包对象
	 * @param [in] parentNode 树形控件父节点
	 * @return 0 成功；-1 失败（数据包为空或无DNS头部）
	 */
int CSnifferUIDlg::printDNSHeader(const Packet &pkt, HTREEITEM &parentNode)
{
	if (pkt.isEmpty() || pkt.dnsh == NULL || parentNode == NULL)
	{
		return -1;
	}
	CString strText, strTmp;
	// 打印DNS标识字段
	strText.Format("标识：0x%04hX (%hu)", ntohs(pkt.dnsh->identifier), ntohs(pkt.dnsh->identifier));
	m_treeCtrlPacketDetails.InsertItem(strText, parentNode, 0);

	strText.Format("标志：0x%04hX", ntohs(pkt.dnsh->flags));
	strText += strTmp;

	HTREEITEM DNSFlagNode = m_treeCtrlPacketDetails.InsertItem(strText, parentNode, 0);
	/* 标志子字段 */
	switch (pkt.getDNSFlagsQR())
	{
	case DNS_FLAGS_QR_REQUEST:
		strText = "QR：; 查询报文 （0）";
		break;
	case DNS_FLAGS_QR_REPLY:
		strText = "QR：; 响应报文 （1）";
		break;
	}
	m_treeCtrlPacketDetails.InsertItem(strText, DNSFlagNode, 0);

	switch (pkt.getDNSFlagsOPCODE())
	{
	case DNS_FLAGS_OPCODE_STANDARD_QUERY:
		strText = "OPCODE：标准查询 （0）";
		break;
	case DNS_FLAGS_OPCODE_INVERSE_QUERY:
		strText = "OPCODE：反向查询 （1）";
		break;
	case DNS_FLAGS_OPCODE_SERVER_STATUS_REQUEST:
		strText = "OPCODE：服务器状态请求 （2）";
		break;
	}
	m_treeCtrlPacketDetails.InsertItem(strText, DNSFlagNode, 0);

	switch (pkt.getDNSFlagsAA())
	{
	case 0:
		strText = "AA：非授权回答 （0）";
		break;
	case 1:
		strText = "AA：授权回答 （1）";
		break;
	}
	m_treeCtrlPacketDetails.InsertItem(strText, DNSFlagNode, 0);

	switch (pkt.getDNSFlagsTC())
	{
	case 0:
		strText = "TC：报文未截断 （0）";
		break;
	case 1:
		strText = "TC：报文截断 （1）";
		break;
	}
	m_treeCtrlPacketDetails.InsertItem(strText, DNSFlagNode, 0);

	switch (pkt.getDNSFlagsRD())
	{
	case 0:
		strText = "RD：0";
		break;
	case 1:
		strText = "RD：希望进行递归查询 （1）";
		break;
	}
	m_treeCtrlPacketDetails.InsertItem(strText, DNSFlagNode, 0);

	switch (pkt.getDNSFlagsRA())
	{
	case 0:
		strText = "RA：服务器不支持递归查询 （0）";
		break;
	case 1:
		strText = "RA：服务器支持递归查询 （1）";
		break;
	}
	m_treeCtrlPacketDetails.InsertItem(strText, DNSFlagNode, 0);

	strText.Format("Z：保留（%d）", pkt.getDNSFlagsZ());
	m_treeCtrlPacketDetails.InsertItem(strText, DNSFlagNode, 0);

	switch (pkt.getDNSFlagsRCODE())
	{
	case DNS_FLAGS_RCODE_NO_ERROR:
		strText = "RCODE：无差错 （0）";
		break;
	case DNS_FLAGS_RCODE_FORMAT_ERROR:
		strText = "RCODE：格式差错 （1）";
		break;
	case DNS_FLAGS_RCODE_SERVER_FAILURE:
		strText = "RCODE：DNS服务器问题 （2）";
		break;
	case DNS_FLAGS_RCODE_NAME_ERROR:
		strText = "RCODE：域名不存在或出错 （3）";
		break;
	case DNS_FLAGS_RCODE_NOT_IMPLEMENTED:
		strText = "RCODE：查询类型不支持 （4）";
		break;
	case DNS_FLAGS_RCODE_REFUSED:
		strText = "RCODE：在管理上禁止 （5）";
		break;
	default:
		strText.Format("RCODE：保留（%d）", pkt.getDNSFlagsRCODE());
		break;
	}
	m_treeCtrlPacketDetails.InsertItem(strText, DNSFlagNode, 0);

	strText.Format("查询记录数：%hu", ntohs(pkt.dnsh->questions));
	m_treeCtrlPacketDetails.InsertItem(strText, parentNode, 0);

	strText.Format("回答记录数：%hu", ntohs(pkt.dnsh->answer_RRs));
	m_treeCtrlPacketDetails.InsertItem(strText, parentNode, 0);

	strText.Format("授权回答记录数：%hu", ntohs(pkt.dnsh->authority_RRs));
	m_treeCtrlPacketDetails.InsertItem(strText, parentNode, 0);

	strText.Format("附加信息记录数：%hu", ntohs(pkt.dnsh->additional_RRs));
	m_treeCtrlPacketDetails.InsertItem(strText, parentNode, 0);

	return 0;
}

	/**
	 * @brief 将DNS类型枚举值转换为字符串描述
	 * @param [in] type DNS类型值（网络字节序）
	 * @return 类型对应的字符串描述
	 */
CString CSnifferUIDlg::DNSType2CString(const u_short &type)
{
	CString strType;
	// 根据DNS类型枚举值返回对应描述
	switch (ntohs(type))
	{
	case DNS_TYPE_A:
		strType = "Type A（IPv4地址记录）";
		break;
	case DNS_TYPE_NS:
		strType = "Type NS（名称服务器记录）";
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
		strType.Format(" Type 未知（%hu）,", ntohs(type));
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
		strClass.Format("Class 未知（%hu）", ntohs(classes));
		break;
	}
	return strClass;
}

	/**
	 * @brief 打印DNS查询部分信息到树形控件
	 * @param [in] DNSQuery DNS查询数据指针
	 * @param [in] questions 查询记录数
	 * @param [in] parentNode 树形控件父节点
	 * @return 处理的字节数；-1 失败（参数为空）
	 */
int CSnifferUIDlg::printDNSQuery(char *DNSQuery, const u_short &questions, HTREEITEM &parentNode)
{
	if (DNSQuery == NULL && parentNode == NULL)
	{
		return -1;
	}
	CString strText, strTmp;
	// 创建查询部分根节点
	HTREEITEM DNSQueryNode = m_treeCtrlPacketDetails.InsertItem("查询部分：", parentNode, 0);

	/* 查询部分 */

	char *p = DNSQuery;
	// if (questions < 10)
	//{
	for (int queryNum = 0; queryNum < questions; ++queryNum)
	{
		char *name = (char *)malloc(strlen(p) + 1);
		translateNameInDNS(name, p);

		/* 跳过域名字段 */
		p += strlen(p) + 1;
		strText.Format("%s：", name);

		DNS_Query *DNSQuery = (DNS_Query *)p;
		strText += DNSType2CString(DNSQuery->type) + ", ";
		strText += DNSClass2CString(DNSQuery->classes);
		m_treeCtrlPacketDetails.InsertItem(strText, DNSQueryNode, 0);

		/* 跳过查询类型和查询类字段 */
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
		strText = "回答部分：";
		break;
	case DNS_RESOURCE_RECORD_TYPE_AUTHORITY:
		strText = "授权回答部分：";
		break;
	case DNS_RESOURCE_RECORD_TYPE_ADDITIONAL:
		strText = "附加信息部分：";
		break;
	}
	HTREEITEM DNSResourceRecordNode = m_treeCtrlPacketDetails.InsertItem(strText, parentNode, 0);

	for (int count = 0; count < 1; ++count) // count < resourceRecordNum; ++count)
	{

		if (*(u_char *)p == 0xC0)
		{
			// name
			strText = getNameInDNS(p, pDNSHeader) + "：";

			// 指向type，class，ttl
			p += 2; // 2 = 0xC0 + 偏移量
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

		// 指向资源数据长度
		p += sizeof(DNS_ResourceRecord);
		u_short dataLength = *(u_short *)p;
		strTmp.Format("资源数据长度：%hu 字节", dataLength);
		strText += strTmp + ", ";

		// 指向资源数据
		p += sizeof(u_short);

		switch (ntohs(pRecord->type))
		{
		case DNS_TYPE_A:
			strText += "IP地址： " + IPAddr2CString(*(IP_Address *)p);
			break;
		case DNS_TYPE_NS:
			strText += "名字服务器： " + IPAddr2CString(*(IP_Address *)p);
			break;
		case DNS_TYPE_CNAME:
		{

			CString strCName = getNameInDNS(p, pDNSHeader);
			strText += "别名：" + strCName;
			// m_treeCtrlPacketDetails.InsertItem(strText, parentNode, 0);
			// free(cname);
			break;
		}
		default:
			/*strTmp.Format("Type 未知(%hu),", ntohs(pRecord->type));
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
	/* 解析dhcp首部 */
	strText.Format("报文类型：%d", pkt.dhcph->op);
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);
	strText.Format("硬件类型：%d", pkt.dhcph->htype);
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	strText.Format("硬件地址长度：%d", pkt.dhcph->hlen);
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	strText.Format("跳数：%d", pkt.dhcph->hops);
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	strText.Format("事务ID：0x%08lX", ntohl(pkt.dhcph->xid));
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	strText.Format("客户启动时间：%hu", ntohs(pkt.dhcph->secs));
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	strText.Format("标志：0x%04hX", ntohs(pkt.dhcph->flags));
	switch (ntohs(pkt.dhcph->flags) >> 15)
	{
	case DHCP_FLAGS_BROADCAST:
		strText += "（广播）";
		break;
	case DHCP_FLAGS_UNICAST:
		strText += "（单播）";
		break;
	}
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	strText = "客户机IP地址：" + IPAddr2CString(pkt.dhcph->ciaddr);
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	strText = "你的（客户）IP地址：" + IPAddr2CString(pkt.dhcph->yiaddr);
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	strText = "服务器IP地址：" + IPAddr2CString(pkt.dhcph->siaddr);
	;
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	strText = "网关IP地址：" + IPAddr2CString(pkt.dhcph->giaddr);
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	/*  解析dhcp首部剩余部分 */
	CString strChaddr;
	for (int i = 0; i < 6; ++i)
	{
		strTmp.Format("%02X", pkt.dhcph->chaddr[i]);
		strChaddr += strTmp + "-";
	}
	strChaddr.Delete(strChaddr.GetLength() - 1, 1);

	strText = "客户机MAC地址：" + strChaddr;
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	strText = "服务器主机名：";
	strTmp.Format("%s", pkt.dhcph->snamer);
	strText += strTmp;
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	strText = "引导文件名：";
	strTmp.Format("%s", pkt.dhcph->file);
	strText += strTmp;
	m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

	// 跳过引导文件名
	u_char *p = (u_char *)pkt.dhcph->file + 128;

	if (ntohl(*(u_long *)p) == 0x63825363)
	{
		strText = "Magic cookie: DHCP";
		m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);
	}

	// 跳过magic cookie
	p += 4;

	while (*p != 0xFF)
	{
		switch (*p)
		{
		case DHCP_OPTIONS_DHCP_MESSAGE_TYPE:
		{
			strText = "选项：（53）DHCP报文类型";
			switch (*(p + 2))
			{
			case 1:
				strText += "（Discover）";
				break;
			case 2:
				strText += "（Offer）";
				break;
			case 3:
				strText += "（Request）";
				break;
			case 4:
				strText += "（Decline）";
				break;
			case 5:
				strText += "（ACK）";
				break;
			case 6:
				strText += "（NAK）";
				break;
			case 7:
				strText += "（Release）";
				break;
			case 8:
				strText += "（Inform）";
				break;
			}
			HTREEITEM DHCPOptionNode = m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

			strText.Format("长度：%d", *(++p));
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			strText.Format("DHCP：%d", *(++p));
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			// 指向下一个选项
			++p;
		}
		break;

		case DHCP_OPTIONS_REQUESTED_IP_ADDRESS:
		{
			strText = "选项：（50）请求IP地址";
			HTREEITEM DHCPOptionNode = m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

			strText.Format("长度：%d", *(++p));
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			IP_Address *addr = (IP_Address *)(++p);
			strText = "地址：" + IPAddr2CString(*addr);
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			// 指向下一个选项
			p += 4;
		}
		break;

		case DHCP_OPTIONS_IP_ADDRESS_LEASE_TIME:
		{
			strText = "选项：（51）IP地址租约时间";
			HTREEITEM DHCPOptionNode = m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

			strText.Format("长度：%d", *(++p));
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			u_int time = *(++p);
			strText.Format("租约时间：%u", time);
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			// 指向下一个选项
			p += 4;
		}
		break;

		case DHCP_OPTIONS_CLIENT_IDENTIFIER:
		{
			strText = "选项：（61）客户机标识";
			HTREEITEM DHCPOptionNode = m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format("长度：%d", len);
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			strText = "硬件类型：";
			if (*(++p) == 0x01)
			{
				strText += "以太网（0x01）";
				m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

				MAC_Address *addr = (MAC_Address *)(++p);
				strText = "客户机标识：" + MACAddr2CString(*addr);
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
			strText = "选项：（60）供应商类标识";
			HTREEITEM DHCPOptionNode = m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format("长度：%d", len);
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			int count = 0;
			strText = "供应商类标识：";
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
			strText = "选项：（54）服务器标识";
			HTREEITEM DHCPOptionNode = m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format("长度：%d", len);
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			IP_Address *addr = (IP_Address *)(++p);
			strText = "服务器标识：" + IPAddr2CString(*addr);
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			p += 4;
		}
		break;

		case DHCP_OPTIONS_SUBNET_MASK:
		{

			strText = "选项：（1）子网掩码";
			HTREEITEM DHCPOptionNode = m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format("长度：%d", len);
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			IP_Address *submask = (IP_Address *)(++p);
			strText = "子网掩码：" + IPAddr2CString(*submask);
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			p += 4;
		}
		break;

		case DHCP_OPTIONS_ROUTER_OPTION:
		{

			strText = "选项：（3）路由器";
			HTREEITEM DHCPOptionNode = m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format("长度：%d", len);
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			int count = 0;
			while (count < len)
			{
				IP_Address *addr = (IP_Address *)(++p);
				strText = "路由器：" + IPAddr2CString(*addr);
				m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

				count += 4;
				p += 4;
			}
		}
		break;

		case DHCP_OPTIONS_DOMAIN_NAME_SERVER_OPTION:
		{
			strText = "选项：（6）DNS服务器";
			HTREEITEM DHCPOptionNode = m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format("长度：%d", len);
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			int count = 0;
			++p;
			while (count < len)
			{
				IP_Address *addr = (IP_Address *)(p);
				strText = "DNS服务器：" + IPAddr2CString(*addr);
				m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

				count += 4;
				p += 4;
			}
		}
		break;

		case DHCP_OPTIONS_HOST_NAME_OPTION:
		{
			strText = "选项：（12）主机名";
			HTREEITEM DHCPOptionNode = m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format("长度：%d", len);
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			int count = 0;
			strText = "主机名：";

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
			strText.Format("选项：（%d）", *p);
			HTREEITEM DHCPOptionNode = m_treeCtrlPacketDetails.InsertItem(strText, DHCPNode, 0);

			int len = *(++p);
			strText.Format("长度：%d", len);
			m_treeCtrlPacketDetails.InsertItem(strText, DHCPOptionNode, 0);

			// 指向选项内容
			++p;

			// 跳过选项内容
			p += len;
		}
		break;
		} // switch

	} // while
	strText = "选项：（255）结束";
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
		strText = "HTTP（请求）";
	}
	else if (ntohs(pkt.tcph->srcport) == PORT_HTTP)
	{
		strText = "HTTP（响应）";
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
	/* 获取选中行的行号 */
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
	else if (CDDS_ITEMPREPAINT == pNMCD->nmcd.dwDrawStage) // 一个Item(一行)被绘画前
	{
		COLORREF itemColor;

		CString *pStrPktProtocol = (CString *)(pNMCD->nmcd.lItemlParam); // 在printListCtrlPacketList(pkt)里将数据包的protocol字段传递过来
		if (!pStrPktProtocol->IsEmpty())
		{
			if (*pStrPktProtocol == "ARP")
			{
				itemColor = RGB(255, 182, 193); // 红色
			}
			else if (*pStrPktProtocol == "ICMP")
			{
				itemColor = RGB(186, 85, 211); // 紫色
			}
			else if (*pStrPktProtocol == "TCP")
			{
				itemColor = RGB(144, 238, 144); // 绿色
			}
			else if (*pStrPktProtocol == "UDP")
			{
				itemColor = RGB(100, 149, 237); // 蓝色
			}
			else if (*pStrPktProtocol == "DNS")
			{
				itemColor = RGB(135, 206, 250); // 浅蓝色
			}
			else if (*pStrPktProtocol == "DHCP")
			{
				itemColor = RGB(189, 254, 76); // 淡黄色
			}
			else if (*pStrPktProtocol == "HTTP")
			{
				itemColor = RGB(238, 232, 180); // 黄色
			}
			else
			{
				itemColor = RGB(211, 211, 211); // 灰色
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
		/* 检查过滤器是否启动，若启动了，则只打印符合过滤器的新捕获数据包 */
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

		// 修改状态栏 - 数据包总数、数据包显示个数
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
	UINT uID = pNMHDR->idFrom; // 相当于原WM_COMMAND传递方式的wParam（low-order）, 在wParam中放的则是控件的ID。

	if (pTTT->uFlags & TTF_IDISHWND)
		uID = ::GetDlgCtrlID((HWND)uID);
	if (uID == NULL)
		return FALSE;
	switch (uID)
	{
	case ID_TOOLBARBTN_START:
		pTTT->lpszText = _T("开始捕获");
		break;

	case ID_TOOLBARBTN_STOP:
		pTTT->lpszText = _T("结束捕获");
		break;

	case ID_MENU_FILE_OPEN:
		pTTT->lpszText = _T("打开文件");
		break;

	case ID_MENU_FILE_SAVEAS:
		pTTT->lpszText = _T("另存为");
		break;

	case ID_TOOLBARBTN_CLEAR:
		pTTT->lpszText = _T("清除过滤器");
		break;

	case ID_TOOLBARBTN_FILTER:
		pTTT->lpszText = _T("应用过滤器");
		break;
	}

	return TRUE;
}
void CSnifferUIDlg::OnAcceleratorCtrlG()
{
	m_listCtrlPacketList.SetFocus();

	/* 垂直滚动条自动跳到选中位置*/
	int selItemIndex = m_listCtrlPacketList.GetSelectionMark();
	int topItemIndex = m_listCtrlPacketList.GetTopIndex(); // 列表中当前最顶层可见项的下标
	CRect rc;
	m_listCtrlPacketList.GetItemRect(selItemIndex, rc, LVIR_BOUNDS); // 获得一行的大小rc
	CSize sz(0, (selItemIndex - topItemIndex) * rc.Height());				 // （selItemIndex - topItemIndex）表示滚动量n，>0表示向下滚动n行，<0表示向上滚动n行，
	// *rc.Height（行高）是因为scroll（）按像素值滚动
	m_listCtrlPacketList.Scroll(sz); // 滚动到选中位置
}
void CSnifferUIDlg::OnKeydownList1(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLVKEYDOWN pLVKeyDow = reinterpret_cast<LPNMLVKEYDOWN>(pNMHDR);
	bool selectedItemChangedFlag = false;
	int selectedItemIndex = m_listCtrlPacketList.GetSelectionMark();
	/* 判断按下的键是否为方向键上或方向键下*/
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

	/* 选中行发送变化，打印数据包信息和字节流 */
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

	/* 将计数转换为'.' */
	while (*p)
	{
		if (!isalnum(*p) && *p != '-')
		{
			*p = '.';
		}
		++p;
	}

	/* 将域名整体向前移1位 */
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
	/* 将计数转换为'.' */
	for (int i = 0; i < strName.GetLength(); ++i)
	{
		if (!isalnum(strName.GetAt(i)) && strName.GetAt(i) != '-')
		{
			strName.SetAt(i, '.');
		}
	}

	/* 将域名整体向前移1位 */
	if (canMove)
	{
		for (int i = 0; i < strName.GetLength(); ++i)
		{
			strName.SetAt(i, strName.GetAt(i + 1));
		}
	}
	return strName;
}
/* DNS资源记录数据部分转换 将带有指针0xc0的data2转换为不带指针的data1 offset为到dns首部的偏移量*/
void translateData(const DNS_Header *dnsh, char *data1, char *data2, const int data2_len)
{
	char *p = data2;
	int count = 0, i = 0;

	/* 遍历data2 */
	while (count < data2_len)
	{
		/* 指针 */
		if (*(u_char *)p == 0xC0)
		{
			++p;

			/* 读取指针所指向的数据 */
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

	// name中无0xC0指针
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
	CFileDialog dlgFile(TRUE, _T(".pcap"), NULL, OFN_FILEMUSTEXIST | OFN_HIDEREADONLY, _T("pcap文件 (*.pcap)|*.pcap|所有文件 (*.*)|*.*||"), NULL);
	if (dlgFile.DoModal() == IDOK)
	{
		CString openFilePath = dlgFile.GetPathName();
		CString openFileName = dlgFile.GetFileName();
		if (dlgFile.GetFileExt() != "pcap") // 检查文件扩展名
		{
			AfxMessageBox("无法打开文件" + openFileName + "，请检查文件扩展名");
			return;
		}
		if (openFileName == m_openFileName) // 检查文件名，避免重复打开
		{
			AfxMessageBox("不能重复打开相同文件" + openFileName);
			return;
		}
		if (m_catcher.openAdapter(openFilePath))
		{
			m_openFileName = openFileName;													// 保存文件名
			AfxGetMainWnd()->SetWindowText(openFileName);						// 修改标题栏为文件名
			m_menu.EnableMenuItem(ID_MENU_FILE_OPEN, MF_ENABLED);		// 启用菜单项"打开"
			m_menu.EnableMenuItem(ID_MENU_FILE_CLOSE, MF_ENABLED);	// 启用菜单项"关闭"
			m_menu.EnableMenuItem(ID_MENU_FILE_SAVEAS, MF_ENABLED); // 启用菜单项"另存为"

			m_toolBarMain.GetToolBarCtrl().EnableButton(ID_MENU_FILE_OPEN, TRUE);		// 启用工具栏按钮"打开"
			m_toolBarMain.GetToolBarCtrl().EnableButton(ID_MENU_FILE_SAVEAS, TRUE); // 启用工具栏按钮"另存为"

			m_listCtrlPacketList.DeleteAllItems();
			m_treeCtrlPacketDetails.DeleteAllItems();
			m_editCtrlPacketBytes.SetWindowText(_T(""));
			m_pool.clear();

			m_pktDumper.setPath(openFilePath);
			m_catcher.startCapture(MODE_CAPTURE_OFFLINE);
			m_fileOpenFlag = true;

			CString status = "已打开文件：" + openFileName;
			updateStatusBar(status, -1, -1);
			// m_statusBar.SetPaneText(0, status, true);		// 修改状态栏
		}
	}
}
void CSnifferUIDlg::OnMenuFileClose()
{
	if (m_fileOpenFlag)
	{
		AfxGetMainWnd()->SetWindowText(_T("SnifferUI"));			 // 修改标题栏
		m_menu.EnableMenuItem(ID_MENU_FILE_OPEN, MF_ENABLED);	 // 启用菜单项"打开"
		m_menu.EnableMenuItem(ID_MENU_FILE_CLOSE, MF_GRAYED);	 // 禁用菜单项"关闭"
		m_menu.EnableMenuItem(ID_MENU_FILE_SAVEAS, MF_GRAYED); // 禁用菜单项"另存为"

		m_toolBarMain.GetToolBarCtrl().EnableButton(ID_MENU_FILE_OPEN, TRUE);		 // 启用工具栏按钮"打开"
		m_toolBarMain.GetToolBarCtrl().EnableButton(ID_MENU_FILE_SAVEAS, FALSE); // 禁用工具栏按钮"另存为"

		m_listCtrlPacketList.DeleteAllItems();
		m_treeCtrlPacketDetails.DeleteAllItems();
		m_editCtrlPacketBytes.SetWindowText(_T(""));
		m_pool.clear();

		m_openFileName = "";
		updateStatusBar(CString("就绪"), 0, 0);
	}
}
void CSnifferUIDlg::OnMenuFileSaveAs()
{
	CString saveAsFilePath = _T("");
	CString dumpFilePath = m_pktDumper.getPath();
	CString defaultFileName = m_pktDumper.getPath();
	CFileDialog dlgFile(FALSE, _T(".pcap"), defaultFileName, OFN_OVERWRITEPROMPT, _T("pcap文件 (*.pcap)|*.pcap|所有文件 (*.*)|*.*||"), NULL);

	if (dlgFile.DoModal() == IDOK)
	{
		saveAsFilePath = dlgFile.GetPathName();
		m_pktDumper.dump(saveAsFilePath);
		AfxGetMainWnd()->SetWindowText(dlgFile.GetFileName());
		m_statusBar.SetPaneText(0, "已保存至：" + saveAsFilePath, true);
	}
}
void CSnifferUIDlg::OnMenuFileClearCache()
{
	if (clearDirectory(".\\tmp\\"))
	{
		updateStatusBar("缓存文件已清空", -1, -1);
	}
	else
	{
		updateStatusBar("无缓存文件可清理", -1, -1);
	}
}

void CSnifferUIDlg::OnMenuFileExit()
{
	exit(0);
}

void CSnifferUIDlg::OnTvnSelchangedTree1(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMTREEVIEW pNMTreeView = reinterpret_cast<LPNMTREEVIEW>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
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
	// TODO: 在此添加控件通知处理程序代码
	*pResult = 0;
}
