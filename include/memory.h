#ifndef __REFLECTIVE_DLL_INJECTION_MEMORY_H_
#define __REFLECTIVE_DLL_INJECTION_MEMORY_H_
#pragma once

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// Compares the two strings.
int memory_strcmp_ascii(const char* str_one, const char* str_two);

// Compares the two strings.
int memory_strcmp_win(const wchar_t* str_one, const wchar_t* str_two);

// Sets the memory with specific value.
void* memory_memset(void* target, int val, unsigned int size);

// Moves the source memory data to the destination buffer.
void* memory_memmove(void* dest, const void* src, unsigned int size);

#ifdef __cplusplus
}
#endif

#endif  // __REFLECTIVE_DLL_INJECTION_MEMORY_H_