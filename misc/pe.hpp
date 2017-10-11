#pragma once

#ifdef __linux__
#include <sys/mman.h>
#else
#include <Windows.h>
#endif

namespace hooklib {
	class pe {
	public:
		pe(HMODULE mod)
			: m_module(mod) {}

		template< typename T > inline T dos_offset(uintptr_t offset) {
			return reinterpret_cast<T>(reinterpret_cast<uintptr_t>(get_dos_header()) + offset);
		}

		PIMAGE_DOS_HEADER get_dos_header() {
			auto dos = (PIMAGE_DOS_HEADER)m_module;

			if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
				return nullptr;
			}

			return dos;
		}

		PIMAGE_NT_HEADERS get_nt_headers() {
			auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uintptr_t>(get_dos_header()) + get_dos_header()->e_lfanew);

			if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) {
				return nullptr;
			}

			return nt;
		}

		PIMAGE_IMPORT_DESCRIPTOR get_import_descriptor() {
			auto nt = get_nt_headers();
			if (!nt)
				return 0;

			auto dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
			if (!dir.VirtualAddress)
				return 0;

			return dos_offset< PIMAGE_IMPORT_DESCRIPTOR >(dir.VirtualAddress);
		}

		PIMAGE_EXPORT_DIRECTORY get_export_directory() {
			auto nt = get_nt_headers();
			if (!nt)
				return 0;

			auto dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			if (!dir.VirtualAddress)
				return 0;

			return dos_offset< PIMAGE_EXPORT_DIRECTORY >(dir.VirtualAddress);
		}
	protected:
		HMODULE m_module;
	};
};