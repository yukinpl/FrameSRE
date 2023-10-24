#pragma once

namespace daniel
{

namespace network
{

class Udpheader
{

private :
	uint16_t txPort ;
	uint16_t rxPort ;
	uint16_t length ;
	uint16_t checksum ;

public :
	Udpheader( uint8_t const * p , uint8_t const & len ) ;

public :
	uint16_t const & GetTxPort() const ;
	uint16_t const & GetRxPort() const ;

} ;

} // namespace network

} // namespace daniel