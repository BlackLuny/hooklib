#pragma once

#include "../crypto/fnvstring.hpp"
#include "../misc/pe.hpp"
#include "../misc/memory_protection.hpp"

namespace hooklib {
	class EAT : protected pe {
	protected:
		IMAGE_EXPORT_DIRECTORY *m_dir;
		
	public:
		EAT( HMODULE mod ) : pe( mod ), m_dir( get_export_directory() ) {};

		template< typename t = uintptr_t > t hook( uint32_t hash, void *func ) {
			if( !m_dir )
				return 0;
			
			uint32_t *names		= dos_offset< uint32_t * >( m_dir->AddressOfNames );
			uint32_t *funcs		= dos_offset< uint32_t * >( m_dir->AddressOfFunctions );
			uint16_t *ords		= dos_offset< uint16_t * >( m_dir->AddressOfNameOrdinals );
			if( !names || !funcs || !ords )
				return 0;

			// todo; check for export by ordinal?
			for( uint32_t i = 0; i < m_dir->NumberOfNames; i++ ) {
				std::string name( dos_offset<char *>(names[i]) );
				if( name.empty() )
					continue;

				if( hash::FNVString(name) == hash ) {
					//uintptr_t *func_ptr = &funcs[ ords[i] ];
					//uintptr_t old_ptr	= ( uintptr_t ) m_module + *func_ptr;
					//
					//printf( "%s 0x%x, base: 0x%llx\n", name.c_str(), hash::FNVString(name).get(), old_ptr );
					//
					//memory_protection< uintptr_t * > prot( func_ptr, PAGE_READWRITE );
					//
					//*func_ptr = (uintptr_t)( (uintptr_t)func - (uintptr_t)m_module );
					//
					//prot.restore();

					//uintptr_t func_ptr = ( uintptr_t ) m_module + funcs[ords[i]];
					//PDWORD64 old = (PDWORD64)&funcs[ ords[ i ] ];
					//uintptr_t haha = func_ptr;
					//
					//memory_protection< PDWORD64 > prot( old, PAGE_READWRITE, 8 );
					//
					////funcs[ords[i]] = (uintptr_t)( (uintptr_t)func - (uintptr_t)m_module );
					//*old = (uintptr_t)( (uintptr_t)func - (uintptr_t)m_module );
					//
					//prot.restore();
					//
					//printf( "%s 0x%x, base: 0x%llx\n", name.c_str(), hash::FNVString(name).get(), func_ptr );

					//return (t)haha;
				}
			}

			return 0;
		}
	};
}