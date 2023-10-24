#include "pch.h"
#include "NetW.h"


bool daniel::npcap::NetW::GetNetworkInterfaces( std::vector< Interface > & ifVec )
{
	pcap_if_t * pAll = nullptr ;


	char errbuf[ PCAP_ERRBUF_SIZE + 1 ] ;

	int res = pcap_findalldevs( & pAll , errbuf ) ;
	if( -1 == res || nullptr == pAll )
	{
		return false ;
	}

	pcap_if_t * pOne = pAll ;
	ifVec.clear() ;

	do
	{
		if( PCAP_IF_LOOPBACK & pOne->flags ) // except loopback device
		{
			continue ;
		}

		if( nullptr == pOne->addresses ) // except invalid device
		{
			continue ;
		}

		Interface ifs( reinterpret_cast< int64_t >( pOne->addresses ) , pOne->name , pOne->description ) ;
		ifVec.emplace_back( ifs ) ;

	} while( nullptr != ( pOne = pOne->next ) ) ;

	pcap_freealldevs( pAll ) ;

	return true ;
}


bool daniel::npcap::NetW::SendFrame( char const * ifName , uint8_t const * pDat , size_t const & length )
{
	char errbuf[ PCAP_ERRBUF_SIZE ] ;

	pcap_t * pcap_fp  = pcap_open_live( ifName , 65536 , 1 , 20 , errbuf ) ;

	if( nullptr == pcap_fp )
	{
		return false ;
	}

	int res = pcap_sendpacket( pcap_fp , pDat , static_cast< int const >( length ) ) ;
	if( 0 != res )
	{
		return false ;
	}

	pcap_close( pcap_fp ) ;
	pcap_fp = nullptr ;

	return true ;
}