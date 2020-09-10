#define _CRT_SECURE_NO_DEPRECATE

#include <windows.h>
#include <stdio.h>
#include "injector.h"

unsigned char* read_bytes(unsigned char* fname);

int main()
{
	// read in bytes of file
	char* buf = read_bytes("./resources/helloworld.exe");
	if (!buf)
		return 1;

	// Create portable executable
	int error_code = 0;
	exe_handle_t handle = exe_handle_new((void*)buf, 1, &error_code);
	
	// Call the entry-point of the portable executable.
	exe_handle_main(handle);

	// Free portable executable and bytes of physical executable from
	// memory.
	exe_handle_free(handle);
	free(buf);

	return error_code;
}

unsigned char* read_bytes(unsigned char* fname)
{
	FILE* fp = fopen(fname, "rb");
	if (!fp)
		return NULL;
	
	// find length of the file
	fseek(fp, 0, SEEK_END);
	long long file_len = ftell(fp);
	rewind(fp);

	// read bytes into memory
	unsigned char* buf = (unsigned char*)malloc((file_len + 1) * sizeof(unsigned char));
	if (!buf)
		return NULL;

	fread(buf, file_len, 1, fp);
	fclose(fp);

	return buf;
}