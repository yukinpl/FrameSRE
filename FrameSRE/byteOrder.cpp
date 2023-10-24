#include "pch.h"
#include "byteOrder.h"


uint32_t daniel::npcap::GetUint32( ByteOrder const & endian , uint8_t const * p )
{
	uint32_t value = 0 ;

	if( ByteOrder::BIG_ENDIAN == endian )
	{
		value
			= ( ( p[ 0 ] << 24 ) & 0xFF000000 )
			| ( ( p[ 1 ] << 16 ) & 0x00FF0000 )
			| ( ( p[ 2 ] <<  8 ) & 0x0000FF00 )
			| ( ( p[ 3 ] <<  0 ) & 0x000000FF ) ;
	}
	else if( ByteOrder::LITTLE_ENDIAN == endian )
	{
		value
			= ( ( p[ 3 ] << 24 ) & 0xFF000000 )
			| ( ( p[ 2 ] << 16 ) & 0x00FF0000 )
			| ( ( p[ 1 ] <<  8 ) & 0x0000FF00 )
			| ( ( p[ 0 ] <<  0 ) & 0x000000FF ) ;
	}
	else
	{
		value = 0 ;
	}

	return value ;
}


uint16_t daniel::npcap::GetUint16( ByteOrder const & endian , uint8_t const * p )
{
	uint16_t value = 0 ;

	if( ByteOrder::BIG_ENDIAN == endian )
	{
		value
			= ( ( p[ 0 ] << 8 ) & 0xFF00 )
			| ( ( p[ 1 ] << 0 ) & 0x00FF ) ;
	}
	else if( ByteOrder::LITTLE_ENDIAN == endian )
	{
		value
			= ( ( p[ 1 ] << 8 ) & 0xFF00 )
			| ( ( p[ 0 ] << 0 ) & 0x00FF ) ;
	}
	else
	{
		value = 0 ;
	}

	return value ;
}