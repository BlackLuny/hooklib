#pragma once

#include <string>
#include <Subauth.h>

namespace hooklib {
	namespace converter {
		static inline std::wstring kernel_to_wide( UNICODE_STRING kernel_string ) {
			return std::wstring( kernel_string.Buffer, kernel_string.Length );
		}

		static inline std::string kernel_to_string( UNICODE_STRING kernel_string ) {
			std::wstring wide_str( kernel_string.Buffer, kernel_string.Length );
			return std::string( wide_str.begin(), wide_str.end() );
		}

		static inline std::string wide_to_string( std::wstring wide_str ) {
			return std::string( wide_str.begin(), wide_str.end() );
		}

		static inline std::wstring string_to_wide( std::string str ) {
			return( std::wstring( str.begin(), str.end() ) );
		}
	};
};