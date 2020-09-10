#ifndef __REFLECTIVE_DLL_INJECTOR_MODULE_H_
#define __REFLECTIVE_DLL_INJECTOR_MODULE_H_
#pragma once

#include <windows.h>
#include "apitable.h"

#ifdef __cplusplus
extern "C" {
#endif

// Error codes.
enum error_code {
	EXE_OK,
	EXE_BAD_PE_FMT,
	EXE_MEMORY_ALLOC_FAIL,
	EXE_INVALID_BASE_RELOC,
	EXE_MODULE_IMPORT_FAIL,
	EXE_PROTECT_SECTION_FAIL,
	EXE_INVALID_ENTRY_POINT,
	EXE_INVALID_WIN32_ENV,
};

// Macro for creating pointer values.
#define MOVE_PTR(t, p, offset) ((t)((unsigned char*)(p) + offset))

// Represents the memory module instance.
struct exe {
	union {
#if _WIN64
		unsigned __int64 img_base;
#else
		unsigned long img_base;
#endif
		HMODULE h_module;
		void* base;
		PIMAGE_DOS_HEADER img_dos_head;
	};                            // `exe` base
	unsigned long size_of_image;  // `exe` size
	unsigned long crc;            // `exe` crc32
	struct api_table* api;        // function table
	int call_entry;               // call exe entry
	int load_ok;                  // `exe` is loaded
	enum error_code error_code;   // last error code
};

// Initialises and calls the portable executable.
int exe_init(struct exe* pe, void* exe_buf); 

// Frees the portable executable.
void exe_free(struct exe* pe);

// Returns a pointer to the function in the executable, specified by `name`.
FARPROC exe_get_fn(struct exe* pe, const char* name);

#ifdef __cplusplus
}
#endif

#endif  // __REFLECTIVE_DLL_INJECTOR_MODULE_H_