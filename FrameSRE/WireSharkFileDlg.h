#pragma once
#include "afxdialogex.h"


#include <string>


class WireSharkFileDlg : public CDialogEx
{
	DECLARE_DYNAMIC( WireSharkFileDlg )

public:
	WireSharkFileDlg( CWnd * pParent = nullptr ) ;
	virtual ~WireSharkFileDlg() ;

#ifdef AFX_DESIGN_TIME
	enum
	{
		IDD = IDD_WIRESHARK_DETAIL
	};
#endif

private :
	std::string path ;
	std::string ifName ;
	CFont m_font ;

private :
	CListCtrl m_list ;

public :
	void SetPcapPath( std::string const & str ) ;
	void SetInterfaceName( std::string const & ifName ) ;

private :
	void SetDefault() ;
	void SetFont() ;
	void LoadPcapFile() ;

private :
	uint64_t Hex2Int( char const * const hexStr , bool & isOverflow ) ;

private :
	BOOL PreTranslateMessage( MSG * pMsg ) ;

protected :
	virtual BOOL OnInitDialog() ;

protected :
	virtual void DoDataExchange( CDataExchange * pDX ) ;

	DECLARE_MESSAGE_MAP()

public:
	afx_msg void OnNMClickListLog( NMHDR * pNMHDR , LRESULT * pResult );
	afx_msg void OnNMDblclkListLog( NMHDR * pNMHDR , LRESULT * pResult );
} ;
