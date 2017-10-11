# hooklib
A small and simple header-only hooking library for x86 / x64 architecture

## features
  - Length disassembly using the [capstone](http://www.capstone-engine.org/) library
  - Header-only, no building or binaries required
  - Follow absolute and relative JMP to real function
  - Follow JMP gate to real function
  - Import Address Table hooking on Windows
  - Raw code detours for x86
  - Raw code detours for x64
  - Variable amount of raw code detour methods to fit size circumstances
  - Overwriting padding if no detour method fits the functions size

## todo
  - Export Address Table hooking on Windows
  - Exception handler based hooking
