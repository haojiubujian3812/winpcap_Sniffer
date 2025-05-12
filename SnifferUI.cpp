// SnifferUI.cpp : Defines the class behaviors for the application.
//

#include "stdafx.h"
#include "SnifferUI.h"
#include "SnifferUIDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
// 使用安全字符类型并增加缓冲区安全检查
static TCHAR THIS_FILE[MAX_PATH] = _T(__FILE__);  // 使用通用字符类型
#endif

/////////////////////////////////////////////////////////////////////////////
// CSnifferUIApp

BEGIN_MESSAGE_MAP(CSnifferUIApp, CWinApp)
	//{{AFX_MSG_MAP(CSnifferUIApp)
	//}}AFX_MSG
	ON_COMMAND(ID_HELP, CWinApp::OnHelp)
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CSnifferUIApp construction

CSnifferUIApp::CSnifferUIApp()
{
	// 启用视觉样式（Windows XP及更高版本）
	// 替换过时的Enable3dControls
	INITCOMMONCONTROLSEX InitCtrls;
	InitCtrls.dwSize = sizeof(InitCtrls);
	InitCtrls.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&InitCtrls);
}

/////////////////////////////////////////////////////////////////////////////
// The one and only CSnifferUIApp object

CSnifferUIApp theApp;

/////////////////////////////////////////////////////////////////////////////
// CSnifferUIApp initialization

BOOL CSnifferUIApp::InitInstance()
{
	// Include the necessary header for LoadAccelerators and related functions  


// Replace the problematic line with the correct function call  
	HACCEL hAccelTable = LoadAccelerators(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDR_ACCELERATOR));
	if (hAccelTable == NULL)
	{
		AfxMessageBox(_T("Failed to load accelerators"));
		return FALSE;
	}
	// 创建并显示主对话框
	CSnifferUIDlg dlg;
	m_pMainWnd = &dlg;

	// 使用安全的重试机制处理对话框创建
	INT_PTR nResponse = IDABORT;

	do
	{
		nResponse = dlg.DoModal();
		if (nResponse == IDOK)
		{
			// 添加异常处理
			try
			{
				// TODO: 处理确定按钮逻辑
			}
			catch (...)
			{
				AfxMessageBox(_T("Operation failed unexpectedly"));
				nResponse = IDABORT;
			}
		}
		else if (nResponse == IDCANCEL)
		{
			// 添加清理逻辑
		}
	} while (nResponse == IDABORT);  // 允许重试机制

	// 安全退出应用程序
	return FALSE;
}