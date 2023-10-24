#pragma once

#include <inttypes.h>

namespace daniel
{

namespace npcap
{

enum class ByteOrder : uint8_t
{
	BIG_ENDIAN = 0 ,
	LITTLE_ENDIAN = 1 ,

	UNKNOWN = 255
} ;


uint32_t GetUint32( ByteOrder const & endian , uint8_t const * p ) ;
uint16_t GetUint16( ByteOrder const & endian , uint8_t const * p ) ;


} // npcap

} // daniel