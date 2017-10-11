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

#include "../assembly/jmp.hpp"
#include "../misc/memory_protection.hpp"

namespace hooklib {
	namespace detour {
		class base_detour {
		public:
			enum opt {
				none			 = 0,
				follow_jmp		 = ( 1 << 0 ),
				follow_jmp_gate  = ( 1 << 1 ),
				fallback_padding = ( 1 << 2 ),
			};

			base_detour(byte *old, byte *dest, opt options = opt::none, cs_mode m = CS_MODE_32, cs_arch a = CS_ARCH_X86 )
				: source(old), hook(dest) {
				cs_open(a, m, &capstone);
				cs_option(capstone, CS_OPT_DETAIL, CS_OPT_ON);

				if( hooklib::assembly::follow_jump( capstone, source ) ) {
					if (options & opt::follow_jmp) {
						source = (byte *)hooklib::assembly::follow_jump(capstone, source);
					}
					else if (options & opt::follow_jmp_gate) {
						source = (byte *)hooklib::assembly::follow_jump_gate(capstone, source);
					}
				}

				if (options & opt::fallback_padding) {
					// todo
				}
			}

			~base_detour() {
				cs_close(&capstone);
			}

			virtual void *commit() { return nullptr; };

			void restore() {
				hooklib::memory_protection< uint8_t * > guard(source, PAGE_EXECUTE_READWRITE);
				std::copy(original_code.begin(), original_code.end(), source);
				guard.restore();
			}

			template< typename T > T get_trampoline() { return reinterpret_cast< T >(original_trampoline); }
		protected:
			void *original_trampoline;

			byte *source;
			byte *hook;

			opt options;

			csh capstone;

			std::vector< uint8_t > original_code;
		};
	};
};