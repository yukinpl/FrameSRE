#include "pch.h"
#include "UdpHeader.h"

daniel::network::Udpheader::Udpheader( uint8_t const * p , uint8_t const & len )
	: txPort( 0 ) , rxPort( 0 ) , length ( 0 ) , checksum( 0 )
{
	if( 8 != len )
	{
		return ;
	}

	txPort   = ( ( p[ 0 ] << 8 ) & 0xFF00 ) | ( ( p[ 1 ] << 0 ) & 0x00FF ) ;
	rxPort   = ( ( p[ 2 ] << 8 ) & 0xFF00 ) | ( ( p[ 3 ] << 0 ) & 0x00FF ) ;
	length   = ( ( p[ 4 ] << 8 ) & 0xFF00 ) | ( ( p[ 5 ] << 0 ) & 0x00FF ) ;
	checksum = ( ( p[ 6 ] << 8 ) & 0xFF00 ) | ( ( p[ 7 ] << 0 ) & 0x00FF ) ;
}


uint16_t const & daniel::network::Udpheader::GetTxPort() const
{
	return txPort ;
}


uint16_t const & daniel::network::Udpheader::GetRxPort() const
{
	return rxPort ;
}