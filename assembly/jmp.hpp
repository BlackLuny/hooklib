#pragma once

#ifdef __linux__
#include <sys/mman.h>
#else
#include <Windows.h>
#endif

#include <iostream>

#include "../detour/detour.hpp"
#include "../platform/platform.hpp"

namespace hooklib {
	namespace assembly {
		static inline uintptr_t relative_to_absolute(uintptr_t position, size_t relative) {
			return ((0xFFFFFFFF - relative) + position) + 1;
		}

		static size_t req_size_instruction(csh capstone, byte *source, size_t size) {
			const uint8_t *addr = (uint8_t *)source;
			size_t code_size = 60;
			uint64_t address = (uint64_t)source;

			cs_insn *insn = cs_malloc(capstone);
			size_t length{};

			while (cs_disasm_iter(capstone, &addr, &code_size, &address, insn)) {
				if (length >= size) break;

				length += insn->size;
			}

			cs_free(insn, 1);

			return (length < size) ? 0 : length;
		}


		static int get_int3_padding(csh capstone, byte *source) {
			const uint8_t *addr = (uint8_t *)((uintptr_t)source - 7);
			size_t code_size = (size_t)source - (size_t)addr;
			uint64_t address = (uint64_t)source;

			cs_insn *insn = cs_malloc(capstone);

			int i3_count = 0;

			while (cs_disasm_iter(capstone, &addr, &code_size, &address, insn)) {
				if (insn->id == X86_INS_INT3) i3_count++;
				else i3_count = 0;
			}

			cs_free(insn, 1);

			return i3_count;
		}

		static uintptr_t follow_jump(csh capstone, byte *source) {
			const uint8_t *addr = source;
			size_t code_size = 15;
			uint64_t address = (uint64_t)source;

			cs_insn *insn = cs_malloc(capstone);
			cs_disasm_iter(capstone, &addr, &code_size, &address, insn);

			if (insn->id == X86_INS_JMP && insn->detail->x86.op_count == 1) {
				if (insn->detail->x86.operands[0].type == X86_OP_IMM) {
					return insn->detail->x86.operands[0].imm;
				}
				else if (insn->detail->x86.operands[0].type == X86_OP_MEM) {
					uintptr_t absolute = (uintptr_t)source + insn->detail->x86.operands[0].mem.disp + insn->size;
					return *(uintptr_t *)absolute;
				}
			}

			cs_free(insn, 1);

			return 0;
		}

		static uintptr_t follow_jump_gate(csh capstone, byte *source) {
			uintptr_t ptr = follow_jump(capstone, source);

			if (!ptr) return ( uintptr_t ) source;

			do {
				ptr = *(uintptr_t *)follow_jump(capstone, (byte *)ptr);
			} while (*(uintptr_t *)follow_jump(capstone, (byte *)ptr) != NULL);

			return ptr;
		}

		// 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0xCC * sizeof uintptr
		static void create_abs_ripjump(byte *from, byte *dest, size_t from_offset = 0, size_t dest_offset = 0) {
			from += from_offset;
			dest += dest_offset;

			*(uint8_t *)((uintptr_t)from) = 0xFF;
			*(uint8_t *)((uintptr_t)from + 1) = 0x25;

#if IS_X64
				*(uint32_t *)((uintptr_t)from + 2) = 0x0;
#else
				*(uint32_t *)((uintptr_t)from + 2) = ( uintptr_t ) from + 6;
#endif

			*(uintptr_t *)((uintptr_t)from + sizeof uint32_t + 2) = (uintptr_t)dest;
		}

		// 0x50, 0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x87, 0x04, 0x24, 0xC3
		static void create_abs_ret64(byte *from, byte *dest, size_t from_offset = 0, size_t dest_offset = 0) {
			from += from_offset;

			*(uint8_t *)((uintptr_t)from) = 0x50;
			*(uint8_t *)((uintptr_t)from + 1) = 0x48;
			*(uint8_t *)((uintptr_t)from + 2) = 0xB8;
			*(uintptr_t *)((uintptr_t)from + 3) = (uintptr_t)dest + dest_offset;
			*(uint8_t *)((uintptr_t)from + sizeof uintptr_t + 3) = 0x48;
			*(uint8_t *)((uintptr_t)from + sizeof uintptr_t + 4) = 0x87;
			*(uint8_t *)((uintptr_t)from + sizeof uintptr_t + 5) = 0x04;
			*(uint8_t *)((uintptr_t)from + sizeof uintptr_t + 6) = 0x24;
			*(uint8_t *)((uintptr_t)from + sizeof uintptr_t + 7) = 0xC3;
		}
	};
};