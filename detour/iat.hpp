#pragma once

#include <memory>

#include "detour.hpp"

#include "../crypto/fnvstring.hpp"
#include "../misc/pe.hpp"
#include "../misc/memory_protection.hpp"

namespace hooklib {
		class IAT : public pe {
		public:
			IAT(HMODULE module) :
				pe( module ) {}

			template< typename T > T hook(uint32_t hash, void *new_function) {
				auto import_module = get_import_descriptor();

				while (*(unsigned short *)import_module != 0) {
					auto thunk = dos_offset< PIMAGE_THUNK_DATA >(import_module->FirstThunk);
					auto tmp = dos_offset< PIMAGE_THUNK_DATA >(import_module->Characteristics);
					auto import = dos_offset< PIMAGE_IMPORT_BY_NAME >(tmp->u1.AddressOfData);

					while (*(unsigned short *)thunk && *(unsigned short *)tmp) {
						if (hash::FNVString(import->Name) == hash) {
							unsigned long old_protection{};

							old_function = thunk->u1.Function;

							hooklib::memory_protection<uintptr_t *> thunk_guard((uintptr_t*)&thunk->u1.Function, PAGE_READWRITE);
							thunk->u1.Function = (uintptr_t)new_function;
							thunk_guard.restore();

							return reinterpret_cast< T >(old_function);
						}

						tmp++;
						thunk++;
						import = dos_offset< PIMAGE_IMPORT_BY_NAME >(tmp->u1.AddressOfData);
					}

					import_module++;
				}

				return T{};
			}

			template< typename T > T hook(std::string import_name, void *new_function) {
				return hook< T >(hash::FNVString(import_name)(), new_function);
			}

			template<typename T = uintptr_t> T get_original() { return (T)old_function; }

			inline void unhook(uint32_t hash) {
				hook<void *>(hash, get_original<void *>());
			}

			inline void unhook(std::string import_name) {
				unhook(hash::FNVString(import_name)());
			}
		protected:
			uintptr_t old_function;
	};
};