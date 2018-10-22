#pragma once
#include "Mini_SM2_CA.h"


// CPassWordDlg 对话框

class CPassWordDlg : public CDialog
{
	DECLARE_DYNAMIC(CPassWordDlg)

public:
	CPassWordDlg(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CPassWordDlg();

// 对话框数据
	enum { IDD = IDD_PW_DIALOG };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	CString m_strPassWord;
	afx_msg void OnBnClickedOk();
};
