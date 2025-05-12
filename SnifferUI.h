// SnifferUI.h : main header file for the SNIFFERUI application
//

#if !defined(AFX_SNIFFERUI_H__F6F0F8D9_180D_4884_AE2B_3F3EF81EC4A8__INCLUDED_)
#define AFX_SNIFFERUI_H__F6F0F8D9_180D_4884_AE2B_3F3EF81EC4A8__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifndef __AFXWIN_H__
#error include 'stdafx.h' before including this file for PCH
#endif

#include "resource.h"		// main symbols
class CSnifferUIApp : public CWinApp
{
public:
	CSnifferUIApp();
public:
	virtual BOOL InitInstance();
	DECLARE_MESSAGE_MAP()
};
#endif