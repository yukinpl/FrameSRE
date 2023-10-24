#include "pch.h"
#include "Interface.h"


daniel::npcap::Interface::Interface()
	: uniqueId( 0 ) , name( "" ) , desc( "" ) 
{

}


daniel::npcap::Interface::Interface( uint64_t const & _uniqueId , char const * _name , char const * _desc )
	: uniqueId( _uniqueId ) , name( _name ) , desc( _desc ) 
{

}


uint64_t const & daniel::npcap::Interface::GetUniqueId() const
{
	return uniqueId ;
}


std::string const & daniel::npcap::Interface::GetName() const
{
	return name ;
}


std::string const & daniel::npcap::Interface::GetDesc() const
{
	return desc ;
}