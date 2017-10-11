#pragma once

#ifdef __linux__
#include <sys/mman.h>
#else
#include <Windows.h>
#endif

#include <iostream>
#include <vector>

#include <x86.h>
#include <capstone.h>

#include "detour.hpp"

namespace hooklib {
	namespace detour {
		class x86 : public base_detour {
		public:
			x86(byte *from, byte *to, opt option = opt::none)
				: base_detour(from, to, option) {}

			void *commit() {
				size_t size = hooklib::assembly::req_size_instruction(capstone, source, 10);
				if (!size) return nullptr;

				uint8_t *trampoline = (uint8_t *)malloc(size + 5);

				hooklib::memory_protection< uint8_t * >(trampoline, PAGE_EXECUTE_READWRITE, size + 5);
				hooklib::memory_protection< uint8_t * > source_protect(source);

				if (!source_protect.rwx()) source_protect.protect(PAGE_EXECUTE_READWRITE);

				original_code.resize(size);
				original_code.assign(source, source + size);

				memcpy(trampoline, source, size);

				*(uint8_t *)((uintptr_t)trampoline + size) = 0xE9;
				*(uintptr_t *)((uintptr_t)trampoline + (size + 1)) = (uintptr_t)(source + size - ((uintptr_t)trampoline + (size + 1))) - 5;

				hooklib::assembly::create_abs_ripjump(source, hook);

				for (int i = 10; i < size; i++) source[i] = 0x90;

				source_protect.restore();

				original_trampoline = trampoline;

				return trampoline;
			}
		};
	};
};