#pragma once


namespace daniel
{

namespace network
{

class FrameHeader
{
	bool isCorrect ;
	bool isIpv4 ;

private :
	uint8_t da[ 6 ] ;
	uint8_t sa[ 6 ] ;
	uint8_t type[ 2 ] ;

public :
	FrameHeader( uint8_t const * p , uint8_t const & len ) ;

public :
	bool const & IsCorrect() const ;
	bool const & IsIpV4() const ;

	uint8_t const * GetDA() const ;
	uint8_t const * GetSA() const ;

} ;

} // namespace network

} // namespace daniel