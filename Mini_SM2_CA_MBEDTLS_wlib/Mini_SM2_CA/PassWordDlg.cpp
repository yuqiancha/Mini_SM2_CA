// PassWordDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "PassWordDlg.h"
#include "MSCUKeyAPI.h"

//#include "CVSKF.h"

// CPassWordDlg 对话框

IMPLEMENT_DYNAMIC(CPassWordDlg, CDialog)

CPassWordDlg::CPassWordDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CPassWordDlg::IDD, pParent)
	, m_strPassWord(_T(""))
{

}

CPassWordDlg::~CPassWordDlg()
{
}

void CPassWordDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT_PW, m_strPassWord);
}


BEGIN_MESSAGE_MAP(CPassWordDlg, CDialog)
	ON_BN_CLICKED(IDOK, &CPassWordDlg::OnBnClickedOk)
END_MESSAGE_MAP()


// CPassWordDlg 消息处理程序

void CPassWordDlg::OnBnClickedOk()
{
	// TODO: 在此添加控件通知处理程序代码
	LPTSTR 		UserPin;
	int			UserPinLen;
	ULONG			trytime;
	CString		str;
	DWORD		dwRet = 0;

	UpdateData(TRUE);
	CStatic *Lable=(CStatic*)GetDlgItem(IDC_STATIC_INFO);
	UserPin=(LPTSTR)m_strPassWord.GetBuffer(0);
	UserPinLen=(int)m_strPassWord.GetLength();

	dwRet = MSC_VerifyUserPIN((BYTE *)UserPin,UserPinLen);
	if(dwRet== 0x9000)
	{
		OnOK();
	}	
	else
	{
		if(dwRet == 0x6983)
		{
			Lable->SetWindowText("用户PIN码已经被锁定，请联系管理员");
		}
		else if((dwRet & 0xFF00) == 0x6300)
		{
					
			if(dwRet == 0x63C0)
			{
				Lable->SetWindowText("用户PIN认证失败，可尝试次数已达上限，请联系管理员");
				((CButton*)GetDlgItem(IDOK))->EnableWindow(0);
			}
			else
			{
				trytime = (dwRet & 0xF);
				str.Format("%d",trytime);
				Lable->SetWindowText("认证用户PIN失败，剩余"+str+"次尝试机会!");
			}
		}
		else
		{
					
			Lable->SetWindowText("认证用户PIN执行不成功!");		
		}
	}

    ((CEdit*)GetDlgItem(IDC_EDIT_PW))->SetWindowText("");

	return ;
}
