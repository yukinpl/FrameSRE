#include "pch.h"
#include "fsHeader.h"


daniel::npcap::fsHeader::fsHeader( uint8_t const * p , uint32_t const & len )
	: endian( ByteOrder::UNKNOWN ) , magic( 0 ) , verMajor( 0 ) , verMinor( 0 ) , timezone( 0 ) , sigfigs( 0 ) , snaplen( 0 ) , network( 0 )
{
	endian = ByteOrder::UNKNOWN ;
	magic  = 0x00000000 ;

	if( 24 != len )
	{
		return ;
	}

	uint8_t mnum[ 4 ] = { p[ 0 ] , p[ 1 ] , p[ 2 ] , p[ 3 ] } ;

	/* */if( 0xA1 == p[ 0 ] && 0xB2 == p[ 1 ] && 0xC3 == p[ 2 ] && 0xD4 == p[ 3 ] )
	{
		endian = ByteOrder::BIG_ENDIAN ;
	}
	else if( 0xD4 == p[ 0 ] && 0xC3 == p[ 1 ] && 0xB2 == p[ 2 ] && 0xA1 == p[ 3 ] )
	{
		endian = ByteOrder::LITTLE_ENDIAN ;
	}
	else
	{
		endian = ByteOrder::UNKNOWN ;
	}

	magic    = GetUint32( endian , & p[  0 ] ) ;
	verMajor = GetUint16( endian , & p[  4 ] ) ;
	verMinor = GetUint16( endian , & p[  6 ] ) ;

	timezone = GetUint32( endian , & p[  8 ] ) ;
	sigfigs  = GetUint32( endian , & p[ 12 ] ) ;

	snaplen  = GetUint32( endian , & p[ 16 ] ) ;
	network  = GetUint32( endian , & p[ 20 ] ) ;
}


bool daniel::npcap::fsHeader::IsCorrect() const
{
	if( !magic )
	{
		return false ;
	}

	return true ;
}


daniel::npcap::ByteOrder const & daniel::npcap::fsHeader::GetEndian() const
{
	return endian ;
}