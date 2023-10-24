#pragma once

#include "byteOrder.h"

namespace daniel
{

namespace npcap
{

class fsHeader
{

private :
	ByteOrder endian ;

private :
	uint32_t magic ;
	uint16_t verMajor ;
	uint16_t verMinor ;
	int32_t  timezone ;
	uint32_t sigfigs ;
	uint32_t snaplen ;
	uint32_t network ;

public :
	fsHeader( uint8_t const * p , uint32_t const & len ) ;
	
	bool IsCorrect() const ;
	ByteOrder const & GetEndian() const ;

} ;

} // namepsace npcap


} // namespace daniel