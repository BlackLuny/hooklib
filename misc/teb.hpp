#pragma once

#ifdef __linux__
#include <sys/mman.h>
#else
#include <Windows.h>
#include <winnt.h>
#include <winternl.h>
#endif

#include "../platform/platform.hpp"

namespace hooklib {
	static inline auto get_teb() {
#if( IS_X64 )
		auto teb = reinterpret_cast< PTEB >(__readgsqword(reinterpret_cast< uintptr_t >(&static_cast< NT_TIB * >(nullptr)->Self)));
#else
		auto teb = reinterpret_cast< PTEB >(__readfsdword(reinterpret_cast< uintptr_t >(&static_cast< NT_TIB * >(nullptr)->Self)));

		return teb;
	}

	static inline auto get_peb() {
		return(get_teb()->ProcessEnvironmentBlock);
	}
};