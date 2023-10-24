#include "pch.h"
#include "App.h"
#include "afxdialogex.h"
#include "WireSharkFileDlg.h"

#include "NetW.h"

#include <string>
#include <fstream>

#include "fsHeader.h"
#include "fspHeader.h"
#include "FrameHeader.h"
#include "IpV4Header.h"
#include "UdpHeader.h"

#include "util.h"


// WireSharkFileDlg 대화 상자

IMPLEMENT_DYNAMIC( WireSharkFileDlg , CDialogEx )

WireSharkFileDlg::WireSharkFileDlg( CWnd * pParent /*=nullptr*/ )
	: CDialogEx( IDD_WIRESHARK_DETAIL , pParent ) , path( "" ) 
{

}


WireSharkFileDlg::~WireSharkFileDlg()
{
}


void WireSharkFileDlg::SetPcapPath( std::string const & str )
{
	path = str ;
}


void WireSharkFileDlg::SetInterfaceName( std::string const & _ifName )
{
	ifName = _ifName ;
}


BOOL WireSharkFileDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog() ;

	SetDefault() ;
	SetFont() ;
	LoadPcapFile() ;

	return TRUE ;
}


void WireSharkFileDlg::SetDefault()
{
	CString tmp( path.c_str() ) ;

	SetDlgItemTextW( IDC_EDIT_PCAP_PATH , tmp ) ;


	m_list.InsertColumn( 0 , _T( "RawData" ) , LVCFMT_LEFT  ,   0 ) ;
	m_list.InsertColumn( 1 , _T( "Order"   ) , LVCFMT_RIGHT ,  60 ) ;
	m_list.InsertColumn( 2 , _T( "DA Mac"  ) , LVCFMT_LEFT  , 160 ) ;
	m_list.InsertColumn( 3 , _T( "SA Mac"  ) , LVCFMT_LEFT  , 160 ) ;
	m_list.InsertColumn( 4 , _T( "DA Ip"   ) , LVCFMT_LEFT  , 160 ) ;
	m_list.InsertColumn( 5 , _T( "SA Ip"   ) , LVCFMT_LEFT  , 160 ) ;
	m_list.InsertColumn( 6 , _T( "Rx Port" ) , LVCFMT_LEFT  ,  80 ) ;
	m_list.InsertColumn( 7 , _T( "Tx Port" ) , LVCFMT_LEFT  ,  80 ) ;
	m_list.InsertColumn( 8 , _T( "Bytes"   ) , LVCFMT_LEFT  ,   0 ) ;

	m_list.SetExtendedStyle( m_list.GetExtendedStyle() | LVS_EX_FULLROWSELECT ) ;
}


void WireSharkFileDlg::SetFont()
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

	CEdit * p = ( CEdit * ) GetDlgItem( IDC_EDIT_PCAP_PATH ) ;
	p->SetFont( & m_font ) ;

	m_list.SetFont( &m_font ) ;

}


BOOL WireSharkFileDlg::PreTranslateMessage( MSG * pMsg )
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

			default :
				break ;

		}
	}

	return CDialogEx::PreTranslateMessage( pMsg ) ;
}



void WireSharkFileDlg::DoDataExchange( CDataExchange * pDX )
{
	CDialogEx::DoDataExchange( pDX ) ;
	DDX_Control( pDX , IDC_LIST_LOG , m_list );
}


BEGIN_MESSAGE_MAP( WireSharkFileDlg , CDialogEx )
	ON_NOTIFY( NM_CLICK , IDC_LIST_LOG , &WireSharkFileDlg::OnNMClickListLog )
	ON_NOTIFY( NM_DBLCLK , IDC_LIST_LOG , &WireSharkFileDlg::OnNMDblclkListLog )
END_MESSAGE_MAP()




void WireSharkFileDlg::LoadPcapFile()
{
	std::ifstream ifs ;
	ifs.open( path.c_str() , std::ios_base::in | std::ios_base::binary ) ;

	if( !ifs.is_open() )
	{
		CloseWindow() ;
	}

	char fsHeaderBuf[ 24 ]  ;
	ifs.read( fsHeaderBuf , 24 ) ;

	daniel::npcap::fsHeader fsHeader( reinterpret_cast< uint8_t * >( fsHeaderBuf ) , 24 ) ;
	daniel::npcap::ByteOrder endian = fsHeader.GetEndian() ;

	if( !fsHeader.IsCorrect() )
	{
		ifs.close() ;

		CloseWindow() ;
	}

	m_list.DeleteAllItems() ;

	int itemCount = 0 ;

	while( !ifs.eof() && ifs.is_open() )
	{
		char fspHeaderBuf[ 16 ] ;
		ifs.read( fspHeaderBuf , 16 ) ;

		daniel::npcap::fspHeader fspHeader( endian , reinterpret_cast< uint8_t * >( fspHeaderBuf ) , 16 ) ;
		if( fspHeader.IsWeird() || 0 >= fspHeader.GetLen() )
		{
			continue ;
		}

		char packet[ 4000 ] ;
		ifs.read( packet , fspHeader.GetLen() ) ;

		daniel::network::FrameHeader frame( reinterpret_cast< uint8_t * >( packet ) , 14 ) ;
		if( !frame.IsCorrect() || !frame.IsIpV4() )
		{
			continue ;
		}

		daniel::network::IpV4Header ipv4( reinterpret_cast< uint8_t * >( packet + 14 ) , 20 ) ;
		if( !ipv4.IsUdp() )
		{
			continue ;
		}

		daniel::network::Udpheader udp( reinterpret_cast< uint8_t * >( packet + 34 ) , 8 ) ;

		CString orderStr ;
		orderStr.Format( _T( "%d" ) , itemCount ) ;

		CString daMac ;
		daMac.Format( _T( "%02X:%02X:%02X:%02X:%02X:%02X" ) ,
			frame.GetDA()[ 0 ] , frame.GetDA()[ 1 ] , frame.GetDA()[ 2 ] ,
			frame.GetDA()[ 3 ] , frame.GetDA()[ 4 ] , frame.GetDA()[ 5 ] ) ;

		CString saMac ;
		saMac.Format( _T( "%02X:%02X:%02X:%02X:%02X:%02X" ) ,
			frame.GetSA()[ 0 ] , frame.GetSA()[ 1 ] , frame.GetSA()[ 2 ] ,
			frame.GetSA()[ 3 ] , frame.GetSA()[ 4 ] , frame.GetSA()[ 5 ] ) ;

		CString daIp ;
		daIp.Format( _T( "%u.%u.%u.%u" ) ,
			ipv4.GetDstIp()[ 0 ] , ipv4.GetDstIp()[ 1 ] , ipv4.GetDstIp()[ 2 ] , ipv4.GetDstIp()[ 3 ] ) ;

		CString saIp ;
		saIp.Format( _T( "%u.%u.%u.%u" ) ,
			ipv4.GetSrcIp()[ 0 ] , ipv4.GetSrcIp()[ 1 ] , ipv4.GetSrcIp()[ 2 ] , ipv4.GetSrcIp()[ 3 ] ) ;

		CString rxPort ;
		rxPort.Format( _T( "%u" ) , udp.GetRxPort() ) ;

		CString txPort ;
		txPort.Format( _T( "%u" ) , udp.GetTxPort() ) ;

		CString rawData ;
		for( uint32_t pos = 0 ; pos < fspHeader.GetLen() ; ++pos ) 
		{
			rawData.AppendFormat( _T( "%02X " ) , static_cast< uint8_t >( packet[ pos ] ) ) ;
		}

		CString bytes ;
		bytes.Format( _T( "%u" ) , fspHeader.GetLen() ) ;

		m_list.InsertItem(  itemCount , _T( "" ) ) ;
		m_list.SetItemText( itemCount , 0 , rawData  ) ;
		m_list.SetItemText( itemCount , 1 , orderStr ) ;
		m_list.SetItemText( itemCount , 2 , daMac    ) ;
		m_list.SetItemText( itemCount , 3 , saMac    ) ;
		m_list.SetItemText( itemCount , 4 , daIp     ) ;
		m_list.SetItemText( itemCount , 5 , saIp     ) ;
		m_list.SetItemText( itemCount , 6 , rxPort   ) ;
		m_list.SetItemText( itemCount , 7 , txPort   ) ;
		m_list.SetItemText( itemCount , 8 , bytes    ) ;

		++itemCount ;

		//m_list.EnsureVisible( m_list.GetItemCount() - 1 , FALSE ) ;
	}
}

void WireSharkFileDlg::OnNMClickListLog( NMHDR * pNMHDR , LRESULT * pResult )
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>( pNMHDR ) ;

	POSITION pos = m_list.GetFirstSelectedItemPosition() ;
	if( nullptr == pos )
	{
		*pResult = 0 ;
		return ;
	}

	int nItem = m_list.GetNextSelectedItem( pos ) ;

	CString order  = m_list.GetItemText( nItem , 1 ) ;
	CString daMac  = m_list.GetItemText( nItem , 2 ) ;
	CString saMac  = m_list.GetItemText( nItem , 3 ) ;
	CString daIp   = m_list.GetItemText( nItem , 4 ) ;
	CString saIp   = m_list.GetItemText( nItem , 5 ) ;
	CString rxPort = m_list.GetItemText( nItem , 6 ) ;
	CString txPort = m_list.GetItemText( nItem , 7 ) ;

	SetDlgItemTextW( IDC_EDIT_ORDER  , order  ) ;
	SetDlgItemTextW( IDC_EDIT_DAMAC  , daMac  ) ;
	SetDlgItemTextW( IDC_EDIT_SAMAC  , saMac  ) ;
	SetDlgItemTextW( IDC_EDIT_DAIP   , daIp   ) ;
	SetDlgItemTextW( IDC_EDIT_SAIP   , saIp   ) ;
	SetDlgItemTextW( IDC_EDIT_RXPORT , rxPort ) ;
	SetDlgItemTextW( IDC_EDIT_TXPORT , txPort ) ;

	*pResult = 0 ;
}


void WireSharkFileDlg::OnNMDblclkListLog( NMHDR * pNMHDR , LRESULT * pResult )
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>( pNMHDR ) ;
	
	POSITION pos = m_list.GetFirstSelectedItemPosition() ;
	if( nullptr == pos )
	{
		*pResult = 0 ;
		return ;
	}

	int nItem = m_list.GetNextSelectedItem( pos ) ;

	CString rawData = m_list.GetItemText( nItem , 0 ) ;
	CString bytes   = m_list.GetItemText( nItem , 8 ) ;

	std::string hex = CW2A( rawData ) ;

	int len =  _ttoi( bytes ) ;

	uint8_t u8[ 4000 ] ;
	memset( u8 , 0 , 4000 ) ;
	for( int pos = 0 ; pos < len ; ++pos )
	{
		std::string tmp = hex.substr( 0 , 2 ) ;
		hex = hex.substr( 3 ) ;

		bool isOverflow = false ;
		u8[ pos ] = static_cast< uint8_t >( daniel::util::Hex2Int( tmp.c_str() , isOverflow ) ) ;
	}

	daniel::npcap::NetW::SendFrame( ifName.c_str() , u8 , len ) ;

	*pResult = 0 ;
}