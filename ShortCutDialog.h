#pragma once
#include "afxcmn.h"


// CShortCutDialog �Ի���

class CShortCutDialog : public CDialog
{
	DECLARE_DYNAMIC(CShortCutDialog)

public:
	CShortCutDialog(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~CShortCutDialog();

	// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_SHORTCUT_DIALOG };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
public:
	CListCtrl m_listCtrlShortCut;
	void initialListCtrl();
	virtual BOOL OnInitDialog();
};
