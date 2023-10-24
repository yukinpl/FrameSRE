#include "pch.h"
#include "framework.h"
#include "App.h"
#include "MainDlg.h"
#include "afxdialogex.h"


#include "NetW.h"
#include "WireSharkFileDlg.h"

#include "fsHeader.h"
#include "fspHeader.h"

#include "util.h"

#include <algorithm>
#include <fstream>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif



MainDlg::MainDlg( CWnd * pParent /*=nullptr*/ )
	: CDialogEx( IDD_FRAMESRE_DIALOG , pParent )
{
	m_hIcon = AfxGetApp()->LoadIcon( IDR_MAINFRAME ) ;
}

void MainDlg::DoDataExchange( CDataExchange * pDX )
{
	CDialogEx::DoDataExchange( pDX ) ;
}

BEGIN_MESSAGE_MAP( MainDlg , CDialogEx )
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED( IDC_BUTTON_FRESH_NETWORK_INTERFACE , & MainDlg::OnBnClickedButtonFreshNetworkInterface )
	ON_BN_CLICKED( IDC_BUTTON_LOAD , &MainDlg::OnBnClickedButtonLoad )
END_MESSAGE_MAP()



BOOL MainDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog() ;

	SetIcon( m_hIcon , TRUE  ) ;
	SetIcon( m_hIcon , FALSE ) ;

	SetDefault() ;
	SetFont() ;
	LoadNetworkInterface() ;

	return TRUE ; 
}


BOOL MainDlg::PreTranslateMessage( MSG * pMsg )
{
	if( WM_KEYDOWN == pMsg->message )
	{
		switch( pMsg->wParam )
		{
			case VK_ESCAPE :
			case VK_RETURN :
			case VK_CANCEL :
				return TRUE ;
				break ;

			default:
				break ;

		}
	}

	return CDialogEx::PreTranslateMessage( pMsg ) ;
}


void MainDlg::SetDefault()
{
	CButton * pChk = ( CButton * ) GetDlgItem( IDC_CHECK_EXCEPT_VIRTUAL ) ;
	pChk->SetCheck( TRUE ) ;
}


void MainDlg::SetFont()
{
	m_font.CreateFontW(
		16 ,                    // size
		 8 ,                    // width
		 0 ,                    // angle - on paint
		 0 ,                    // angle - from baseline
		FW_REGULAR ,            // font weight
		FALSE ,                 // italic
		FALSE ,                 // underline
		FALSE ,                 // centerline - strike
		DEFAULT_CHARSET ,       // charset
		OUT_DEFAULT_PRECIS ,    // precision - for printing
		CLIP_CHARACTER_PRECIS , // precision - for clipping
		PROOF_QUALITY ,         // font quality
		DEFAULT_PITCH ,         // font pitch
		_T( "Cascadia Mono" )   // font family
	) ;

	CComboBox * p = ( CComboBox * ) GetDlgItem( IDC_COMBO_NETWORK_INTERFACE ) ;
	p->SetFont( & m_font ) ;
}


void MainDlg::OnPaint()
{
	if( IsIconic() )
	{
		CPaintDC dc( this ) ; 

		SendMessage( WM_ICONERASEBKGND , reinterpret_cast< WPARAM >( dc.GetSafeHdc() ) , 0 ) ;

		int cxIcon = GetSystemMetrics( SM_CXICON ) ;
		int cyIcon = GetSystemMetrics( SM_CYICON ) ;
		CRect rect;
		GetClientRect( & rect ) ;
		int x = ( rect.Width()  - cxIcon + 1 ) / 2 ;
		int y = ( rect.Height() - cyIcon + 1 ) / 2 ;

		dc.DrawIcon( x , y , m_hIcon ) ;
	}
	else
	{
		CDialogEx::OnPaint() ;
	}
}


HCURSOR MainDlg::OnQueryDragIcon()
{
	return static_cast< HCURSOR >( m_hIcon ) ;
}



void MainDlg::OnBnClickedButtonFreshNetworkInterface()
{
	LoadNetworkInterface() ;
}


void MainDlg::LoadNetworkInterface()
{
	daniel::npcap::NetW::GetNetworkInterfaces( m_ifVec ) ;


	CComboBox * pComboBox = ( CComboBox * ) GetDlgItem( IDC_COMBO_NETWORK_INTERFACE ) ;
	pComboBox->ResetContent() ;

	CButton * pChk = ( CButton * ) GetDlgItem( IDC_CHECK_EXCEPT_VIRTUAL ) ;

	size_t size = m_ifVec.size() ;
	for( size_t pos = 0 ; pos < size ; ++pos )
	{
		daniel::npcap::Interface const & ifs = m_ifVec[ pos ] ;

		uint64_t id = ifs.GetUniqueId() ;
		uint32_t upperId = ( id >> 32 ) & 0x00000000FFFFFFFF ;
		uint32_t lowerId = ( id >>  0 ) & 0x00000000FFFFFFFF ;

		std::string const & ifDesc = ifs.GetDesc() ;
		CString desc( ifDesc.c_str() ) ;

		if( TRUE == pChk->GetCheck() )
		{
			bool isContained = []( std::string const str ) -> bool
			{

				std::string upper = str ;
				std::string keyword = "VIRTUAL" ;
				std::transform( upper.begin() , upper.end() , upper.begin() , []( char s ) { return toupper( s ) ;  } ) ;

				size_t pos = upper.find( keyword ) ;
				if( pos == std::string::npos )
				{
					return false ;
				}

				return true ;
				
			}( ifDesc ) ;

			if( isContained )
			{
				continue ;
			}
		}

		CString tmp ;
		tmp.Format( _T( "0x%08X%08X : %s" ) , upperId , lowerId , desc ) ;

		pComboBox->AddString( tmp ) ;
	}

	if( 0 < pComboBox->GetCount() )
	{
		pComboBox->SetCurSel( 0 ) ;
	}
}



void MainDlg::OnBnClickedButtonLoad()
{
	TCHAR filter[] = _T( "Wireshark file(*.pcap)|*.pcap||" ) ;

	CFileDialog dlg( TRUE , _T( "*.pcap" ) , _T( "" ) , OFN_LONGNAMES , filter ) ;

	std::string path ;
	if( IDOK == dlg.DoModal() )
	{
		path = std::string( CW2A( dlg.GetPathName() ) ) ;
	}
	else
	{
		return ;
	}

	std::ifstream ifs ;
	ifs.open( path.c_str() , std::ios_base::in | std::ios_base::binary ) ;

	if( !ifs.is_open() )
	{
		return ;
	}

	char fsHeaderBuf[ 24 ]  ;
	ifs.read( fsHeaderBuf , 24 ) ;

	daniel::npcap::fsHeader fsHeader( reinterpret_cast< uint8_t * >( fsHeaderBuf ) , 24 ) ;
	daniel::npcap::ByteOrder endian = fsHeader.GetEndian() ;

	if( !fsHeader.IsCorrect() )
	{
		ifs.close() ;

		AfxMessageBox( _T( "Incorrect pcap file" ) ) ;
		return ;
	}

	ifs.close() ;

	CString ifStr ;
	GetDlgItemTextW( IDC_COMBO_NETWORK_INTERFACE , ifStr ) ;

	CString hexCStr = ifStr.Mid( 2 , 16 ) ;
	std::string hexStr = CW2A( hexCStr ) ;

	bool isOverflow = false ;
	uint64_t num = daniel::util::Hex2Int( hexStr.c_str() , isOverflow ) ;

	size_t pos = 0 ;
	bool isFound = false ;
	for( pos = 0 ; pos < m_ifVec.size() ; ++pos )
	{
		uint64_t key = m_ifVec[ pos ].GetUniqueId() ;
		if( num == key )
		{
			isFound = true ;
			break ;
		}
	}

	if( !isFound )
	{
		AfxMessageBox( _T( "Network Interface is not selected or is not existed" ) ) ;
		return ;
	}

	std::string ifName = m_ifVec[ pos ].GetName() ;
	
	WireSharkFileDlg detailDlg ;
	detailDlg.SetPcapPath( path ) ;
	detailDlg.SetInterfaceName( ifName ) ;
	detailDlg.DoModal() ;

}
