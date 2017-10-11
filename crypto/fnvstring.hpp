#pragma once

#include <string>

namespace hooklib {
	namespace hash {
		class FNVString {
		private:
			std::string str;

			inline uint32_t FNVHash(uint8_t byte, uint32_t hash = 0x811C9DC5) {
				return((byte ^ hash) * 0x01000193);
			}
		public:
			FNVString(std::string input) { str = input; }

			inline uint32_t get() {
				uint32_t hash32 = 0x811C9DC5;

				for (char &_byte : str) {
					hash32 = FNVHash(_byte, hash32);
				}

				return(hash32);
			}

			inline operator uint32_t() { return get(); }

			uint32_t operator()() {
				return get();
			}
		};
	};
};