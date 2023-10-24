#include "pch.h"
#include "FrameHeader.h"


daniel::network::FrameHeader::FrameHeader( uint8_t const * p , uint8_t const & len )
	: isCorrect( true ) , isIpv4( false ) ,
	  da{ 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 } ,
	  sa{ 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 } ,
	type{ 0x00 , 0x00 }
{
	isCorrect = true ;

	if( 14 != len )
	{
		isCorrect = false ;
		return ;
	}

	uint8_t pPos = 0 ;

	for( uint8_t pos = 0 ; pos < 6 ; ++pos )
	{
		da[ pos ] = p[ pPos++ ] ;
	}

	for( uint8_t pos = 0 ; pos < 6 ; ++pos )
	{
		sa[ pos ] = p[ pPos++ ] ;
	}

	for( uint8_t pos = 0 ; pos < 2 ; ++pos )
	{
		type[ pos ] = p[ pPos++ ] ;
	}

	isIpv4 = false ;

	if( 0x08 == type[ 0 ] && 0x00 == type[ 1 ] )
	{
		isIpv4 = true ;
	}
}


bool const & daniel::network::FrameHeader::IsCorrect() const
{
	return isCorrect ;
}


bool const & daniel::network::FrameHeader::IsIpV4() const
{
	return isIpv4 ;
}


uint8_t const * daniel::network::FrameHeader::GetDA() const
{
	return da ;
}


uint8_t const * daniel::network::FrameHeader::GetSA() const
{
	return sa ;
}