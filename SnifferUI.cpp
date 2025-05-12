// SnifferUI.cpp : Defines the class behaviors for the application.
//

#include "stdafx.h"
#include "SnifferUI.h"
#include "SnifferUIDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
// ʹ�ð�ȫ�ַ����Ͳ����ӻ�������ȫ���
static TCHAR THIS_FILE[MAX_PATH] = _T(__FILE__);  // ʹ��ͨ���ַ�����
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
	// �����Ӿ���ʽ��Windows XP�����߰汾��
	// �滻��ʱ��Enable3dControls
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
	// ��������ʾ���Ի���
	CSnifferUIDlg dlg;
	m_pMainWnd = &dlg;

	// ʹ�ð�ȫ�����Ի��ƴ���Ի��򴴽�
	INT_PTR nResponse = IDABORT;

	do
	{
		nResponse = dlg.DoModal();
		if (nResponse == IDOK)
		{
			// ����쳣����
			try
			{
				// TODO: ����ȷ����ť�߼�
			}
			catch (...)
			{
				AfxMessageBox(_T("Operation failed unexpectedly"));
				nResponse = IDABORT;
			}
		}
		else if (nResponse == IDCANCEL)
		{
			// ��������߼�
		}
	} while (nResponse == IDABORT);  // �������Ի���

	// ��ȫ�˳�Ӧ�ó���
	return FALSE;
}