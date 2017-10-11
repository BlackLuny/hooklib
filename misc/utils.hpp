#pragma once

#ifdef __linux__
#include <sys/mman.h>
#else
#include <Windows.h>
#endif

namespace hooklib {
	namespace utils {
		HANDLE get_module_by_addr(void *addr) {
			MEMORY_BASIC_INFORMATION mbi;
			if (VirtualQuery(addr, &mbi, sizeof(mbi))) {
				return (HANDLE)mbi.AllocationBase;
			} return nullptr;
		}
	};
};