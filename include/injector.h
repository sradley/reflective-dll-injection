#ifndef __REFLECTIVE_DLL_INJECTOR_INJECTOR_H_
#define __REFLECTIVE_DLL_INJECTOR_INJECTOR_H_
#pragma once

#include <windows.h>

#ifdef __cplusplus 
extern "C" {
#endif

typedef void** exe_handle_t;

// Loads the memory module, and returns the handle to the memory module
// instance, or NULL.
exe_handle_t exe_handle_new(void* exe_buf, int* error);

// Calls the main function of the memory module via dll injection, and returns
// true if successful.
int exe_handle_dll_inject(exe_handle_t exe_handle);

// Gets the process address of the specific function in the memory module, and
// returns the address of the function, or NULL.
FARPROC exe_handle_get_fn(exe_handle_t exe_handle, const char* name);

// Frees the memory module given a memory module handler.
void exe_handle_free(exe_handle_t exe_handle);

#ifdef __cplusplus
}
#endif

#endif  // __REFLECTIVE_DLL_INJECTOR_INJECTOR_H_