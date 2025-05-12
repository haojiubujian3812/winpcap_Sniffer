// ShortCutDialog.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "SnifferUI.h"
#include "ShortCutDialog.h"
#include "afxdialogex.h"


// CShortCutDialog �Ի���

IMPLEMENT_DYNAMIC(CShortCutDialog, CDialog)

CShortCutDialog::CShortCutDialog(CWnd* pParent /*=NULL*/)
	: CDialog(IDD_SHORTCUT_DIALOG, pParent)
{

}

CShortCutDialog::~CShortCutDialog()
{
}

void CShortCutDialog::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST2, m_listCtrlShortCut);
}

void CShortCutDialog::initialListCtrl()
{
	DWORD dwStyle = m_listCtrlShortCut.GetExtendedStyle();	// ����б�ؼ���������
	dwStyle |= LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES;
	m_listCtrlShortCut.SetExtendedStyle(dwStyle);
	m_listCtrlShortCut.GetHeaderCtrl()->EnableWindow(false);// ��ֹ������

	CRect rect;
	m_listCtrlShortCut.GetWindowRect(&rect);
	ScreenToClient(&rect);

	/* ��ӱ�ͷ */
	int index = 0;
	m_listCtrlShortCut.InsertColumn(++index, "��ݼ�", LVCFMT_CENTER, rect.Width() * 0.5);
	m_listCtrlShortCut.InsertColumn(++index, "����", LVCFMT_CENTER, rect.Width() * 0.5);

	UINT mask = LVIF_PARAM | LVIF_TEXT;
	int row = 0;
	int col = 0;

	/* ���һ�� */
	row = m_listCtrlShortCut.InsertItem(mask, m_listCtrlShortCut.GetItemCount(), "Ctrl + G", 0, 0, 0, NULL);
	m_listCtrlShortCut.SetItemText(row, ++col, "������ݰ��б�ѡ�����");

	row = m_listCtrlShortCut.InsertItem(mask, m_listCtrlShortCut.GetItemCount(), "Ctrl + O", 0, 0, 0, NULL);
	m_listCtrlShortCut.SetItemText(row, col, "���ļ�");

	row = m_listCtrlShortCut.InsertItem(mask, m_listCtrlShortCut.GetItemCount(), "Ctrl + W", 0, 0, 0, NULL);
	m_listCtrlShortCut.SetItemText(row, col, "�ر��ļ�");

	row = m_listCtrlShortCut.InsertItem(mask, m_listCtrlShortCut.GetItemCount(), "Ctrl + S", 0, 0, 0, NULL);
	m_listCtrlShortCut.SetItemText(row, col, "���Ϊ");

	row = m_listCtrlShortCut.InsertItem(mask, m_listCtrlShortCut.GetItemCount(), "Alt + F4", 0, 0, 0, NULL);
	m_listCtrlShortCut.SetItemText(row, col, "�˳�");
}


BEGIN_MESSAGE_MAP(CShortCutDialog, CDialog)
END_MESSAGE_MAP()


// CShortCutDialog ��Ϣ�������


BOOL CShortCutDialog::OnInitDialog()
{
	CDialog::OnInitDialog();
	initialListCtrl();
	return TRUE; 
}
