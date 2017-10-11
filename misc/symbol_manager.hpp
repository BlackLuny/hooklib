#pragma once

#ifdef __linux__
#include <sys/mman.h>
#else
#include <Windows.h>
#include <DbgHelp.h>
#endif

#include <algorithm>
#include <vector>

#ifdef _WIN32 || _WIN64
#pragma comment( lib, "DbgHelp.lib" )
#endif

namespace hooklib {
	class symbol_manager {
	public:
		struct sym_data_t {
			std::string sym_name;
			uintptr_t   sym_address;
			size_t      sym_size;

			sym_data_t( std::string name, uintptr_t addr, size_t size )
				: sym_name( name ), sym_address( addr ), sym_size( size ) { }
		};

		using sym_vector = std::vector< sym_data_t >;

		module_symbols( void *module )
			: m_module( module ) {
			::SymInitialize( ::GetCurrentProcess(), 0, true );

			load_symbols();
		}

		~module_symbols() {
			::SymCleanup( ::GetCurrentProcess() );
		}

		auto symbol_from_addr( uintptr_t addr ) {
			auto r = std::find_if(
				std::begin( m_symbolData ), end( m_symbolData ),
				[ & ]( const sym_data_t m ) -> bool {
					return m.sym_address == addr;
				}
			);

			return r;
		}

		auto symbol_from_name( std::string str ) {
			auto r = std::find_if(
				begin( m_symbolData ), end( m_symbolData ),
				[ & ]( const sym_data_t m ) -> bool {
					return m.sym_name.compare( str ) == 0;
				}
			);

			return r;
		}

		void load_symbols() {
			::SymEnumSymbols(
				GetCurrentProcess(),
				reinterpret_cast< unsigned long long >( m_module ),
				"*",
				reinterpret_cast< PSYM_ENUMERATESYMBOLS_CALLBACK >( symbol_callback ),
				this
			);
		}

		auto operator()() const { return m_symbolData; }

		sym_vector get_symbols() const { return m_symbolData; }
		
		template< typename T > T get_module() const { return m_module };

	protected:
		friend static int __stdcall symbol_callback( PSYMBOL_INFO symbol_info, ULONG symbol_size, module_symbols *this_ptr ) {
			this_ptr->m_symbolData.push_back( sym_data_t( std::string( symbol_info->Name, symbol_info->NameLen ), symbol_info->Address, symbol_info->Size ) );

			return 1;
		}

		void *m_module{};

		sym_vector m_symbolData;
	};

};