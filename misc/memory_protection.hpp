#pragma once

#ifdef __linux__
#include <sys/mman.h>
#else
#include <Windows.h>
#endif

namespace hooklib {
	template< typename T >
	class memory_protection {
	public:
		memory_protection(T addr)
			: address(addr), backup(get_protection()), size(sizeof(uintptr_t)) { }

		memory_protection(T addr, unsigned long protection, size_t _size = sizeof(uintptr_t))
			: address(addr), backup(get_protection()), size(_size) {
			protect(protection);
		}

		void restore() {
			VirtualProtect(reinterpret_cast<void *>(address), size, backup, &backup);
		}

		void protect(unsigned long protection) {
			VirtualProtect(reinterpret_cast<void *>(address), size, protection, &backup);
		}

		unsigned long get_protection() {
			MEMORY_BASIC_INFORMATION info;
			VirtualQuery((void *)address, &info, sizeof uintptr_t);

			return info.Protect;
		}

		inline bool rwx() {
			return(get_protection() == PAGE_EXECUTE_READWRITE);
		}
	protected:
		size_t size{ 0xFFFFFFFF };
		T address{};
		ULONG backup;
	};
};