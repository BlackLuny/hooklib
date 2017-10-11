#pragma once

#ifdef __linux__
#include <sys/mman.h>
#else
#include <Windows.h>
#endif

#include <inttypes.h>
#include "../misc/pe.hpp"
#include "../misc/utils.hpp"
#include "../misc/memory_protection.hpp"

#include <vector>

namespace hooklib {
	class VMT {
	public:
		VMT(void *table) {
			if (!table) return;

			vtable = *(uintptr_t **)table;

			old_table.assign(vtable, vtable + size());
		}

		template<typename T = uintptr_t> T hook(unsigned int index, uintptr_t func) {
			if (index > size())
				return T{};

			if (!hooklib::utils::get_module_by_addr((void *)func) || !hooklib::utils::get_module_by_addr((void *)vtable[index]))
				return T{};

			hooklib::memory_protection<uintptr_t> func_guard((uintptr_t)&vtable[index]);

			if (!func_guard.rwx() || func_guard.get_protection() != PAGE_READWRITE) {
				func_guard.protect(PAGE_READWRITE);
			}

			vtable[index] = func;

			func_guard.restore();

			return (T)get_old_function(index);
		}

		void unhook(unsigned int index) {
			hook(index, get_old_function(index));
		}

		template<typename T = uintptr_t> T get_function(unsigned int index) {
			return (T)vtable[index];
		}

		template<typename T = uintptr_t> T get_old_function(unsigned int index) {
			return (T)old_table.at(index);
		}

		inline size_t allocation_size() {
			return size() * sizeof(uintptr_t);
		}
	protected:
		unsigned int size() {
			size_t vfunc_count;
			//while (vtable[vfunc_count]) {
			//	if (!hooklib::utils::get_module_by_addr((void *)vtable[vfunc_count])) break;
			//	vfunc_count++;
			//}

			for (vfunc_count = 0; vtable[vfunc_count] && utils::get_module_by_addr((void *)vtable[vfunc_count]); vfunc_count++) {}

			return vfunc_count;
		}

		uintptr_t *vtable;
		std::vector<uintptr_t> old_table;
	};
};