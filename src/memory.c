#include <windows.h>
#include "memory.h"

#pragma region memory_impl

int memory_strcmp_ascii(const char* str_one, const char* str_two)
{
	unsigned char c1 = 0, c2 = 0;

	while (c1 == c2) {
		c1 = (unsigned char)* str_one++;
		c2 = (unsigned char)* str_two++;

		if (c1 == 0)
			return c1 - c2;
	}

	return c1 - c2;
}

int memory_strcmp_win(const wchar_t* str_one, const wchar_t* str_two)
{
	unsigned short c1 = 0, c2 = 0;

	while (c1 == c2) {
		c1 = (unsigned short)* str_one++;
		if (c1 >= 65 && c1 <= 90)
			c1 = c1 + 32;

		c2 = (unsigned short)* str_two++;
		if (c2 > 65 && c2 < 90)
			c2 = c2 + 32;

		if (c1 == 0)
			return c1 - c2;
	}

	return c1 - c2;
}

#pragma optimize("gtpy", off)

void* memory_memset(void* dest, int val, unsigned int size)
{
	for (unsigned int i = 0; i < size; i++)
		((unsigned char*)dest)[i] = (unsigned char)val;

	return dest;
}

#pragma optimize("gtpy", on)

void* memory_memmove(void* dest, const void* src, unsigned int size)
{
	unsigned char* b1 = 0, *b2 = 0;

	if (src < dest) {
		b1 = (unsigned char*)dest + size - 1;
		b2 = (unsigned char*)src + size - 1;

		for (unsigned int i = size; i > 0; i--)
			*b1-- = *b2--;
	}
	else if (src > dest) {
		b1 = (unsigned char*)dest;
		b2 = (unsigned char*)src;

		for (unsigned int i = size; i > 0; i--)
			*b1++ = *b2++;
	}

	return dest;
}

#pragma endregion memory_impl
