#pragma once

#include <vector>
#include "Interface.h"

class MainDlg : public CDialogEx
{

public :
	MainDlg( CWnd * pParent = nullptr ) ;

	


#ifdef AFX_DESIGN_TIME
	enum
	{
		IDD = IDD_FRAMESRE_DIALOG
	};
#endif

protected :
	virtual void DoDataExchange( CDataExchange * pDX ) ;

private :
	CFont m_font ;
	std::vector< daniel::npcap::Interface > m_ifVec ;

private :
	void SetDefault() ;
	void SetFont() ;
	void LoadNetworkInterface() ;

	BOOL PreTranslateMessage( MSG * pMsg ) ;


protected :
	HICON m_hIcon ;

	virtual BOOL OnInitDialog() ;
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon() ;
	DECLARE_MESSAGE_MAP()
public :
	afx_msg void OnBnClickedButtonFreshNetworkInterface() ;
	afx_msg void OnBnClickedButtonLoad() ;

} ;
