#include "pch.h"
#include "util.h"


uint64_t daniel::util::Hex2Int( char const * const hexStr , bool & isOverflow )
{
	if( !hexStr )
	{
		return false ;
	}

	if( isOverflow )
	{
		isOverflow = false ;
	}

	auto between = []( char val , char c1 , char c2 ) {
		return val >= c1 && val <= c2 ;
	} ;

	size_t len = strlen( hexStr ) ;
	uint64_t result = 0 ;

	for( size_t i = 0 , offset = sizeof( uint64_t ) << 3 ; i < len && ( int ) offset > 0 ; ++i )
	{
		if( between( hexStr[ i ] , '0' , '9' ) )
		{
			result = result << 4 ^ hexStr[ i ] - '0' ;
		}
		else if( between( tolower( hexStr[ i ] ) , 'a' , 'f' ) )
		{
			result = result << 4 ^ tolower( hexStr[ i ] ) - ( 'a' - 10 ) ; // Remove the decimal part;
		}
		offset -= 4 ;
	}

	if( ( ( len + ( ( len % 2 ) != 0 ) ) << 2 ) > ( sizeof( uint64_t ) << 3 ) && isOverflow )
	{
		isOverflow = true ;
	}

	return result ;
}