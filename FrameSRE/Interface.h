#pragma once

#include <string>

namespace daniel
{

namespace npcap
{

class Interface
{

private :
	uint64_t uniqueId ;
	
	std::string name ;
	std::string desc ; // description

public :
	Interface() ;
	Interface( uint64_t const & uniqueId , char const * name , char const * desc ) ;

public :
	uint64_t const & GetUniqueId() const ;
	std::string const & GetName() const ;
	std::string const & GetDesc() const ;
} ;

} // namespace npcap

} // namespace daniel