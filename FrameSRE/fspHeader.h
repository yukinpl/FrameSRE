#pragma once

#include "byteOrder.h"

namespace daniel
{

namespace npcap
{

class fspHeader
{

private :
	ByteOrder endian ;
	bool isWeird ;

private :
	uint32_t tsSec  ;
	uint32_t tsUsec ;
	uint32_t savedLen  ;
	uint32_t actualLen ;

public :
	fspHeader( ByteOrder const & endian , uint8_t const * p , uint8_t const & len ) ;

public :
	bool const & IsWeird() const ;
	uint32_t const & GetLen() const ;

} ;

} // namespace npcap

} // namespace daniel