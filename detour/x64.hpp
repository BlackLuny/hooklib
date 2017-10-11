#pragma once

#include "detour.hpp"

#include <inttypes.h>

namespace hooklib {
	namespace detour {
		class x64 : public base_detour {
		public:
			x64(byte *old, byte *dest, opt option = opt::none)
				: base_detour(old, dest, option, CS_MODE_64) {}

			void *commit() {
				using namespace hooklib;

				size_t size = assembly::req_size_instruction(capstone, source, 16);
				if (!size) return nullptr;

				uint8_t *trampoline = (uint8_t *)malloc(size + 16);

				memory_protection<uint8_t *>(trampoline, PAGE_EXECUTE_READWRITE, size + 16);
				memory_protection<uint8_t *> source_protect(source);

				if (!source_protect.rwx()) source_protect.protect(PAGE_EXECUTE_READWRITE);

				original_code.resize(size);
				original_code.assign(source, source + size);

				memcpy(trampoline, source, size);

				assembly::create_abs_ret64(trampoline, source, size, 16);
				assembly::create_abs_ret64(source, hook);

				for (int i = 16; i < size; i++) source[i] = 0x90;

				source_protect.restore();

				original_trampoline = trampoline;
				return trampoline;
			}
		};
	};
};