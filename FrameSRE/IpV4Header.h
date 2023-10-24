#pragma once

namespace daniel
{

namespace network
{

class IpV4Header
{

private :
	bool isCorrect ;
	bool isUdp ;

private :
	uint8_t  version ;
	uint8_t  ihl ;
	uint8_t  dscp ;
	uint8_t  ecn ;
	uint16_t length ;
	uint16_t id ;
	uint8_t  flags ;
	uint16_t offset ;
	uint8_t  ttl ;
	uint8_t  protocol ;
	uint16_t checksum ;
	uint8_t  srcIp[ 4 ] ;
	uint8_t  dstIp[ 4 ] ;

public :
	IpV4Header( uint8_t const * p , uint16_t const & len ) ;

public :
	bool const & IsUdp() const ;

	uint8_t const * GetSrcIp() const ;
	uint8_t const * GetDstIp() const ;

} ;

} // namespace Network

} // namespace daniel