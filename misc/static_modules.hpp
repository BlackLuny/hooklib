#pragma once

#include <vector>
#include "teb.hpp"

namespace hooklib {
	namespace static_modules {
		// todo: can we please figure out a solution for using DllBase instead of Reserved2?
		static inline HMODULE base() {
			return ( HMODULE )( ( PLDR_DATA_TABLE_ENTRY ) get_peb()->Ldr->InMemoryOrderModuleList.Flink )->Reserved2[ 0 ];
		}

		static inline HMODULE ntdll() {
			return ( HMODULE )( ( PLDR_DATA_TABLE_ENTRY ) get_peb()->Ldr->InMemoryOrderModuleList.Flink[ 0 ].Flink )->Reserved2[ 0 ];
		}

		static inline HMODULE kernel32() {
			return ( HMODULE )( ( PLDR_DATA_TABLE_ENTRY ) get_peb()->Ldr->InMemoryOrderModuleList.Flink[ 0 ].Flink->Flink )->Reserved2[ 0 ];
		}

		static inline HMODULE kernelbase() {
			return ( HMODULE )( ( PLDR_DATA_TABLE_ENTRY ) get_peb()->Ldr->InMemoryOrderModuleList.Flink[ 0 ].Flink->Flink->Flink )->Reserved2[ 0 ];
		}
	};
};