#ifndef __REFLECTIVE_DLL_INJECTOR_APITABLE_H_
#define __REFLECTIVE_DLL_INJECTOR_APITABLE_H_
#pragma once

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// Type definitions
typedef FARPROC(WINAPI* get_fn_addr_fn)(HMODULE, const char*);
typedef HMODULE(WINAPI* get_module_handle_fn)(const char*);
typedef HMODULE(WINAPI* load_lib_ascii_fn)(const char*);
typedef void*(WINAPI* virtual_alloc_fn)(void*, unsigned __int3264, unsigned long, unsigned long);
typedef int(WINAPI* virtual_free_fn)(void*, unsigned __int3264, unsigned long);
typedef int(WINAPI* virtual_protect_fn)(void*, unsigned __int3264, unsigned long, unsigned long*);
typedef HGLOBAL(WINAPI* global_alloc_fn)(unsigned int, unsigned __int3264);
typedef HGLOBAL(WINAPI* global_free_fn)(HGLOBAL);

// Function table for the loader.
struct api_table {
	get_fn_addr_fn get_fn_addr;              // get_fn_addr
	get_module_handle_fn get_module_handle;  // get_module_handle
	load_lib_ascii_fn load_lib_ascii;        // LoadLibraryA
	virtual_alloc_fn virtual_alloc;          // VirtualAlloc
	virtual_free_fn virtual_free;            // VirtualFree
	virtual_protect_fn virtual_protect;      // VirtualProtect
	global_alloc_fn global_alloc;            // GlobalAlloc
	global_free_fn global_free;              // GlobalFree
};

// Creates the function table.
struct api_table* api_table_new();

#ifdef __cplusplus
}
#endif

#endif  // __REFLECTIVE_DLL_INJECTOR_APITABLE_H_
