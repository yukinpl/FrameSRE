#include "pch.h"
#include "IpV4Header.h"


daniel::network::IpV4Header::IpV4Header( uint8_t const * p , uint16_t const & len )
	: isCorrect( true ) , isUdp( false ) ,
	  version( 0 ) , ihl( 0 ) , dscp( 0 ) , ecn( 0 ) , length( 0 ) , id( 0 ) , flags( 0 ) , offset( 0 ) , ttl( 0 ) , protocol( 0 ) , checksum( 0 ) , 
	  srcIp{ 0x00 , 0x00 , 0x00 , 0x00 } , 
	  dstIp{ 0x00 , 0x00 , 0x00 , 0x00 }
{
	isCorrect = true ;

	if( 20 != len )
	{
		isCorrect = false ;
		return ;
	}

	version  = ( ( p[  0 ] >>  4 ) & 0x0F ) ;
	ihl      = ( ( p[  0 ] >>  0 ) & 0x0F ) ;
	dscp     = ( ( p[  1 ] >>  2 ) & 0xFF ) ;
	ecn      = ( ( p[  1 ] >>  0 ) & 0x03 ) ;
	length   = ( ( p[  2 ] <<  8 ) & 0xFF00 ) | ( ( p[  3 ] <<  0 ) & 0x00FF ) ;
	id       = ( ( p[  4 ] <<  8 ) & 0xFF00 ) | ( ( p[  5 ] <<  0 ) & 0x00FF ) ;
	flags    = ( ( p[  6 ] >>  5 ) & 0x07 ) ;
	offset   = ( ( p[  6 ] <<  8 ) & 0x1F00 ) | ( ( p[  7 ] <<  0 ) & 0x00FF ) ;
	ttl      = p[ 8 ] ;
	protocol = p[ 9 ] ;
	checksum = ( ( p[ 10 ] <<  8 ) & 0xFF00 ) | ( ( p[ 11 ] <<  0 ) & 0x00FF ) ;

	srcIp[ 0 ] = p[ 12 ] ;
	srcIp[ 1 ] = p[ 13 ] ;
	srcIp[ 2 ] = p[ 14 ] ;
	srcIp[ 3 ] = p[ 15 ] ;

	dstIp[ 0 ] = p[ 16 ] ;
	dstIp[ 1 ] = p[ 17 ] ;
	dstIp[ 2 ] = p[ 18 ] ;
	dstIp[ 3 ] = p[ 19 ] ;

	isUdp = ( 0x11 == protocol ) ? true : false ;
}


bool const & daniel::network::IpV4Header::IsUdp() const
{
	return isUdp ;
}


uint8_t const * daniel::network::IpV4Header::GetSrcIp() const
{
	return srcIp ;
}


uint8_t const * daniel::network::IpV4Header::GetDstIp() const
{
	return dstIp ;
}