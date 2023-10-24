#pragma once

#include "pcap.h"
#include "Interface.h"
#include <vector>

namespace daniel
{

namespace npcap
{


class NetW
{

public :
	static bool GetNetworkInterfaces( std::vector< Interface > & interVec ) ;
	static bool SendFrame( char const * ifName , uint8_t const * pDat , size_t const & length ) ;


} ;

} // namespace npcap

} // namespace daniel