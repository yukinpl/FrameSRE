#include "pch.h"
#include "fspHeader.h"


daniel::npcap::fspHeader::fspHeader( ByteOrder const & _endian , uint8_t const * p , uint8_t const & len )
	: endian( _endian ) , isWeird( false ) , tsSec( 0 ) , tsUsec( 0 ) , savedLen( 0 ) , actualLen( 0 ) 
{
	isWeird = false ;

	if( 16 != len )
	{
		isWeird = true ;
		return ;
	}

	tsSec     = GetUint32( endian , & p[  0 ] ) ;
	tsUsec    = GetUint32( endian , & p[  4 ] ) ;
	savedLen  = GetUint32( endian , & p[  8 ] ) ;
	actualLen = GetUint32( endian , & p[ 12 ] ) ;

	if( savedLen != actualLen )
	{
		isWeird = true ;
	}
}


bool const & daniel::npcap::fspHeader::IsWeird() const
{
	return isWeird ;
}


uint32_t const & daniel::npcap::fspHeader::GetLen() const
{
	return savedLen ;
}