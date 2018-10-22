// Mini_SM2_CADlg.h : 头文件
//

#pragma once


// CMini_SM2_CADlg 对话框
class CMini_SM2_CADlg : public CDialog
{
// 构造
public:
	CMini_SM2_CADlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_MINI_SM2_CA_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButtonGenrootcer();
public:
	afx_msg void OnBnClickedButtonGenusercer();
public:
	afx_msg void OnBnClickedButtonImportcert();
public:
	afx_msg void OnBnClickedButtonVerifyp10();
public:
	afx_msg void OnBnClickedButtonGenuserp10();
public:
	afx_msg void OnBnClickedButtonGenrootkey();
public:
	afx_msg void OnBnClickedButtonGenrootp10();

public:
	bool WriteRootKeyPair(BYTE *bPriKey, int nPriKeyLen, BYTE *bPubKey, int nPubKeyLen);
	bool ReadRootKeyPair(BYTE *bPriKey, int nPriKeyLen, BYTE *bPubKey, int nPubKeyLen);
	bool WriteRootCert(BYTE *bRootCert, int nRootCertLen);
	bool ReadRootCert(BYTE *bRootCert, int *nRootCertLen);

	afx_msg void OnBnClickedCheck1();
	afx_msg void OnBnClickedCheck2();
	afx_msg void OnBnClickedButtonGenuserkey();
	afx_msg void OnBnClickedCheck3();
};
