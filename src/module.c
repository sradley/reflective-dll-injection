#include <windows.h>
#include "module.h"
#include "memory.h"

#pragma region forward_declaration

#define CRC32_POLY 0x04C10DB7L

#if _WIN64

#define IMAGE_FILE_MACHINE IMAGE_FILE_MACHINE_AMD64
#define HDR_MAGIC IMAGE_NT_OPTIONAL_HDR64_MAGIC
#define BASE_LEFT_MASK 0xffffffff00000000

#else

#define IMAGE_FILE_MACHINE IMAGE_FILE_MACHINE_I386
#define HDR_MAGIC IMAGE_NT_OPTIONAL_HDR32_MAGIC
#define BASE_LEFT_MASK 0

#endif

// Type definitions.
typedef int(WINAPI* dll_main_fn)(HMODULE, unsigned long, void*);

// `exe_t` functions.
int exe_is_valid_pe_format(struct exe* pe, void* exe_buf);
int exe_map_sections(struct exe* pe, void* exe_buf);
int exe_relocate_base(struct exe* pe);
int exe_resolve_import_table(struct exe* pe);
int exe_set_mem_protect_status(struct exe* pe);
int exe_execute_tls_callback(struct exe* pe);
int exe_call_entry(struct exe* pe, unsigned long reason);
FARPROC exe_get_exported_fn(struct exe* pe, const char* name);
void exe_unmap(struct exe* pe);
PIMAGE_NT_HEADERS exe_get_img_nt_head(struct exe* pe);

// Utility functions.
unsigned int calc_crc32(unsigned int init_num, void* buf,
	unsigned int buf_size);

static int PROTECTION_MATRIX[2][2][2] = {
	{
		{PAGE_NOACCESS, PAGE_WRITECOPY},
		{PAGE_READONLY, PAGE_READWRITE},
	},
	{
		{PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY},
		{PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE},
	},
};

#pragma endregion forward_declaration

#pragma region module_impl

int exe_init(struct exe* pe, void* exe_buf)
{
	if (pe == NULL || pe->api == NULL || exe_buf == NULL)
		return 0;
	pe->error_code = EXE_OK;

	// verify file format and map PE header and section table into memory
	if (!exe_is_valid_pe_format(pe, exe_buf) || !exe_map_sections(pe, exe_buf))
		return 0;

	// relocate the module base and resolve the import table
	if (!exe_relocate_base(pe) || !exe_resolve_import_table(pe)) {
		exe_unmap(pe);
		return 0;
	}

	pe->crc = calc_crc32(0, pe->base, pe->size_of_image);

	// correct the protect flag for all section pages
	if (!exe_set_mem_protect_status(pe)) {
		exe_unmap(pe);
		return 0;
	}

	if (!exe_execute_tls_callback(pe))
		return 0;

	return 1;
}

void exe_free(struct exe* pe)
{
	if (pe != NULL) {
		pe->error_code = EXE_OK;
		if (pe->call_entry)
			exe_call_entry(pe, DLL_PROCESS_DETACH);

		exe_unmap(pe);
	}
}

FARPROC exe_get_fn(struct exe* pe, const char* name)
{
	if (pe != NULL && name != NULL) {
		// get the address of the specific function
		pe->error_code = EXE_OK;
		return exe_get_exported_fn(pe, name);
	}

	return NULL;
}

// Verifies the format of the buffer content and returns true if the data is a
// valid PE format.
int exe_is_valid_pe_format(struct exe* pe, void* exe_buf)
{
	// some input validation
	if (pe == NULL || pe->api == NULL)
		return 0;

	// get the dos header
	PIMAGE_DOS_HEADER img_dos_head = (PIMAGE_DOS_HEADER)exe_buf;

	// check the MZ signature
	if (IMAGE_DOS_SIGNATURE != img_dos_head->e_magic) {
		pe->error_code = EXE_BAD_PE_FMT;
		return 0;
	}

	// check PE signature
	PIMAGE_NT_HEADERS img_nt_head = MOVE_PTR(PIMAGE_NT_HEADERS, exe_buf, img_dos_head->e_lfanew);
	if (IMAGE_NT_SIGNATURE != img_nt_head->Signature) {
		pe->error_code = EXE_BAD_PE_FMT;
		return 0;
	}

	// check the machine type
	if (IMAGE_FILE_MACHINE == img_nt_head->FileHeader.Machine) {
		if (HDR_MAGIC != img_nt_head->OptionalHeader.Magic) {
			pe->error_code = EXE_BAD_PE_FMT;
			return 0;
		}
	} else {
		pe->error_code = EXE_BAD_PE_FMT;
		return 0;
	}

	return 1;
}

// Maps all the sections and returns true if successful.
int exe_map_sections(struct exe* pe, void* exe_buf)
{
	// some input validation
	if (pe == NULL || pe->api == NULL || exe_buf == NULL)
		return 0;

	// convert to IMAGE_DOS_HEADER
	PIMAGE_DOS_HEADER img_dos_head = (PIMAGE_DOS_HEADER)exe_buf;

	// get the pointer to IMAGE_NT_HEADERS
	PIMAGE_NT_HEADERS img_nt_head = MOVE_PTR(PIMAGE_NT_HEADERS, img_dos_head,
		img_dos_head->e_lfanew);

	// get the section count and the section header
	int num_sections = img_nt_head->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER img_section_head = MOVE_PTR(PIMAGE_SECTION_HEADER, img_nt_head,
		sizeof(IMAGE_NT_HEADERS));

	// find the last section limit
	unsigned long img_size_limit = 0;
	for (int i = 0; i < num_sections; i++) {
		if (img_section_head[i].VirtualAddress != 0) {
			if (img_size_limit < img_section_head[i].VirtualAddress +
					img_section_head[i].SizeOfRawData) {
				img_size_limit =
					img_section_head[i].VirtualAddress + img_section_head[i].SizeOfRawData;
			}
		}
	}

	// reserve virtual memory
	void* base = pe->api->virtual_alloc((void*)img_nt_head->OptionalHeader.ImageBase,
		img_size_limit, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	// failed to reserve space at ImageBase, then it's up to the system
	if (base == NULL) {
		// reserve memory in arbitrary address
		base = pe->api->virtual_alloc(NULL, img_size_limit, MEM_RESERVE | MEM_COMMIT,
			PAGE_READWRITE);

		// failed again, return false
		if (base == NULL) {
			pe->error_code = EXE_MEMORY_ALLOC_FAIL;
			return 0;
		}
	}

	// commit memory for PE header
	void* dest = pe->api->virtual_alloc(base, img_nt_head->OptionalHeader.SizeOfHeaders,
		MEM_COMMIT, PAGE_READWRITE);

	// copy the data of PE header to the memory allocated
	memory_memmove(dest, exe_buf, img_nt_head->OptionalHeader.SizeOfHeaders);

	// store the base address of this module
	pe->base = dest;
	pe->size_of_image = img_nt_head->OptionalHeader.SizeOfImage;
	pe->load_ok = 1;

	// get the DOS header, NT header and Section header from the new PE header
	// buffer
	img_dos_head = (PIMAGE_DOS_HEADER)dest;
	img_nt_head = MOVE_PTR(PIMAGE_NT_HEADERS, img_dos_head, img_dos_head->e_lfanew);
	img_section_head = MOVE_PTR(PIMAGE_SECTION_HEADER, img_nt_head, sizeof(IMAGE_NT_HEADERS));

	// map all section data into the memory
	void* section_base = NULL, *section_data_src = NULL;
	for (int i = 0; i < num_sections; i++) {
		if (img_section_head[i].VirtualAddress != 0) {
			// get the section base
			section_base = MOVE_PTR(void*, base, img_section_head[i].VirtualAddress);

			if (img_section_head[i].SizeOfRawData == 0) {
				unsigned long size = 0;

				if (img_section_head[i].Misc.VirtualSize > 0)
					size = img_section_head[i].Misc.VirtualSize;
				else
					size = img_nt_head->OptionalHeader.SectionAlignment;

				if (size > 0) {
					// if the size is zero, but the section alignment is not
					// zero, then allocate memory with the alignment
					dest = pe->api->virtual_alloc(section_base, size, MEM_COMMIT, PAGE_READWRITE);
					if (dest == NULL) {
						pe->error_code = EXE_MEMORY_ALLOC_FAIL;
						return 0;
					}

					// always use position from file to support alignments that
					// are smaller than the page size
					memory_memset(section_base, 0, size);
				}
			} else {
				// commit this section to target address
				dest = pe->api->virtual_alloc(section_base, img_section_head[i].SizeOfRawData,
					MEM_COMMIT, PAGE_READWRITE);
				if (dest == NULL) {
					pe->error_code = EXE_MEMORY_ALLOC_FAIL;
					return 0;
				}

				section_data_src = MOVE_PTR(void*, exe_buf, img_section_head[i].PointerToRawData);
				memory_memmove(dest, section_data_src, img_section_head[i].SizeOfRawData);
			}

			// get the next section header
			img_section_head[i].Misc.PhysicalAddress = (unsigned long)(unsigned __int64)dest;
		}
	}

	return 1;
}

// Relocates the module and returns true if successful.
int exe_relocate_base(struct exe* pe)
{
	// some input validation
	if (pe == NULL || pe->img_dos_head == NULL)
		return 0;
	
	// get the delta of the real image base
	PIMAGE_NT_HEADERS img_nt_head = exe_get_img_nt_head(pe);
	LONGLONG base_delta = ((unsigned char*)pe->img_base -
		(unsigned char*)img_nt_head->OptionalHeader.ImageBase);

	// if this module has been loaded to the img_base, no need to do relocation
	if (base_delta == 0)
		return 1;

	unsigned long virtual_addr =
		img_nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	unsigned long size =
		img_nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

	if (virtual_addr == 0 || size == 0)
		return 1;

	PIMAGE_BASE_RELOCATION img_base_reloc = MOVE_PTR(PIMAGE_BASE_RELOCATION, pe->base,
		virtual_addr);

	if (img_base_reloc == NULL) {
		pe->error_code = EXE_INVALID_BASE_RELOC;
		return 0;
	}

	while ((img_base_reloc->VirtualAddress + img_base_reloc->SizeOfBlock) != 0) {
		unsigned short* reloc_data =
			MOVE_PTR(unsigned short*, img_base_reloc, sizeof(IMAGE_BASE_RELOCATION));

		int num_of_reloc_data =
			(img_base_reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(unsigned short);

		for (int i = 0; i < num_of_reloc_data; i++) {
			if (IMAGE_REL_BASED_HIGHLOW == (reloc_data[i] >> 12)) {
				unsigned long* addr = (unsigned long*)(pe->img_base +
					img_base_reloc->VirtualAddress + (reloc_data[i] & 0x0fff));
				*addr += (unsigned long)base_delta;
			}

#ifdef _WIN64
			if (IMAGE_REL_BASED_DIR64 == (reloc_data[i] >> 12)) {
				unsigned __int64* addr = (unsigned __int64*)(pe->img_base +
					img_base_reloc->VirtualAddress + (reloc_data[i] & 0x0fff));
				*addr += base_delta;
			}
#endif
			img_base_reloc = MOVE_PTR(PIMAGE_BASE_RELOCATION, img_base_reloc,
				img_base_reloc->SizeOfBlock);
		}
	}

	return 1;
}

// Resolves the import table and returns true if successful.
int exe_resolve_import_table(struct exe* pe)
{
	if (pe == NULL || pe->api == NULL || pe->img_dos_head == NULL)
		return 0;

	PIMAGE_NT_HEADERS img_nt_head = exe_get_img_nt_head(pe);

	unsigned long virtual_addr =
		img_nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	unsigned long size =
		img_nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

	if (virtual_addr == 0 || size == 0)
		return 1;

	PIMAGE_IMPORT_DESCRIPTOR img_import_desc = MOVE_PTR(PIMAGE_IMPORT_DESCRIPTOR, pe->base,
		virtual_addr);

	for (; img_import_desc->Name; img_import_desc++) {
		// get the dependent module name
		char* dll_name = MOVE_PTR(char*, pe->base, img_import_desc->Name);

		// get the module handle
		HMODULE h_module = pe->api->get_module_handle(dll_name);

		// load the module
		if (h_module == NULL)
			h_module = pe->api->load_lib_ascii(dll_name);

		// failed to load the module
		if (h_module == NULL) {
			pe->error_code = EXE_MODULE_IMPORT_FAIL;
			return 0;
		}

		// get the first thunk
		PIMAGE_THUNK_DATA first_thunk = NULL;
		if (img_import_desc->OriginalFirstThunk) {
			first_thunk = MOVE_PTR(PIMAGE_THUNK_DATA, pe->base,
				img_import_desc->OriginalFirstThunk);
		} else {
			first_thunk = MOVE_PTR(PIMAGE_THUNK_DATA, pe->base, img_import_desc->FirstThunk);
		}

		// import address table thunk
		PIMAGE_THUNK_DATA iat_thunk = MOVE_PTR(PIMAGE_THUNK_DATA, pe->base,
			img_import_desc->FirstThunk);

		for (; first_thunk->u1.AddressOfData; first_thunk++, iat_thunk++) {
			FARPROC fn = NULL;
			if (IMAGE_SNAP_BY_ORDINAL(first_thunk->u1.Ordinal)) {
				fn = pe->api->get_fn_addr(h_module,
					(const char*)IMAGE_ORDINAL(first_thunk->u1.Ordinal));
			} else {
				PIMAGE_IMPORT_BY_NAME img_import_by_name = MOVE_PTR(PIMAGE_IMPORT_BY_NAME,
					pe->base, first_thunk->u1.AddressOfData);
				fn = pe->api->get_fn_addr(h_module, (const char*) & (img_import_by_name->Name));
			}

			// write into import address table
#if _WIN64
			iat_thunk->u1.Function = (unsigned __int64)fn;
#else
			iat_thunk->u1.Function = (unsigned long)fn;
#endif
		}
	}

	return 1;
}

// Sets the memory protection states for all of the sections and returns true
// if successful.
int exe_set_mem_protect_status(struct exe* pe)
{
	// some input validation
	if (pe == NULL || pe->api == NULL)
		return 0;

	PIMAGE_NT_HEADERS img_nt_head = exe_get_img_nt_head(pe);
	int section_count = img_nt_head->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER img_section_head = MOVE_PTR(PIMAGE_SECTION_HEADER, img_nt_head,
		sizeof(IMAGE_NT_HEADERS));

	unsigned __int64 base_left = pe->img_base & BASE_LEFT_MASK;

	for (int i = 0; i < section_count; i++) {
		unsigned __int64 section_base = (img_section_head[i].Misc.PhysicalAddress | base_left);
		unsigned long section_size = img_section_head[i].SizeOfRawData;

		if (section_size == 0)
			continue;

		// get the section characteristics
		unsigned long section_characteristics = img_section_head[i].Characteristics;

		// check if it is discardable
		if (section_characteristics & IMAGE_SCN_MEM_DISCARDABLE) {
			pe->api->virtual_free((void*)section_base, section_size, MEM_DECOMMIT);
			continue;
		}

		// check if it is executable, readable, writable
		int is_exec = 0, is_read = 0, is_write = 0;
		if (section_characteristics & IMAGE_SCN_MEM_EXECUTE)
			is_exec = 1;
		if (section_characteristics & IMAGE_SCN_MEM_READ)
			is_read = 1;
		if (section_characteristics & IMAGE_SCN_MEM_WRITE)
			is_write = 1;

		unsigned long pflag = PROTECTION_MATRIX[is_exec][is_read][is_write];
		if (section_characteristics & IMAGE_SCN_MEM_NOT_CACHED)
			pflag |= PAGE_NOCACHE;

		int old_pflag = 0;
		int res = pe->api->virtual_protect((void*)section_base, section_size, pflag, &old_pflag);
		if (!res) {
			pe->error_code = EXE_PROTECT_SECTION_FAIL;
			return 0;
		}
	}

	return 1;
}

// Executes the TLS callback function and returns true if successful.
int exe_execute_tls_callback(struct exe* pe)
{
	if (pe == NULL || pe->img_dos_head == NULL)
		return 0;

	PIMAGE_NT_HEADERS img_nt_head = exe_get_img_nt_head(pe);
	IMAGE_DATA_DIRECTORY img_dir_entry_tls =
		img_nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

	if (img_dir_entry_tls.VirtualAddress == 0)
		return 1;

	PIMAGE_TLS_DIRECTORY tls =
		(PIMAGE_TLS_DIRECTORY)(pe->img_base + img_dir_entry_tls.VirtualAddress);
	PIMAGE_TLS_CALLBACK* cb = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;

	if (cb)
		while (*cb)
			(*cb++)((void*)pe->h_module, DLL_PROCESS_ATTACH, NULL);

	return 1;
}

// Calls the module entry and returns true if successful.
int exe_call_entry(struct exe* pe, unsigned long reason)
{
	if (pe == NULL || pe->img_dos_head == NULL)
		return 0;

	PIMAGE_NT_HEADERS img_nt_head = exe_get_img_nt_head(pe);
	dll_main_fn fn_module_entry = NULL;

	// If there is no entry point return false
	if (img_nt_head->OptionalHeader.AddressOfEntryPoint == 0)
		return 0;

	fn_module_entry = MOVE_PTR(dll_main_fn, pe->base,
		img_nt_head->OptionalHeader.AddressOfEntryPoint);

	if (fn_module_entry == NULL) {
		pe->error_code = EXE_INVALID_ENTRY_POINT;
		return 0;
	}

	return fn_module_entry(pe->h_module, reason, NULL);
}

// Gets the exported function address and returns if the address of the
// function if successful, otherwise it returns NULL.
FARPROC exe_get_exported_fn(struct exe* pe, const char* name)
{
	if (pe == NULL || pe->img_dos_head == NULL)
		return NULL;

	PIMAGE_NT_HEADERS img_nt_head = exe_get_img_nt_head(pe);
	PIMAGE_EXPORT_DIRECTORY img_export_dir = MOVE_PTR(PIMAGE_EXPORT_DIRECTORY, pe->base,
		img_nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	unsigned long* addr_of_names = MOVE_PTR(unsigned long*, pe->base,
		img_export_dir->AddressOfNames);
	unsigned short* addr_of_name_ordinals = MOVE_PTR(unsigned short*, pe->base,
		img_export_dir->AddressOfNameOrdinals);
	unsigned long* addr_of_fns = MOVE_PTR(unsigned long*, pe->base,
		img_export_dir->AddressOfFunctions);

	int num_fns = img_export_dir->NumberOfFunctions;
	for (int i = 0; i < num_fns; ++i) {
		const char* fn_name = MOVE_PTR(const char*, pe->base, addr_of_names[i]);

		if (memory_strcmp_ascii(name, fn_name) == 0) {
			unsigned short ordinal = addr_of_name_ordinals[i];
			return MOVE_PTR(FARPROC, pe->base, addr_of_fns[ordinal]);
		}
	}

	return NULL;
}

// Unmaps all the sections and returns true if successful.
void exe_unmap(struct exe* pe)
{
	if (pe == NULL || pe->api == NULL || pe->load_ok == 0 || pe->base == NULL)
		return;

	pe->api->virtual_free(pe->base, 0, MEM_RELEASE);

	pe->base = NULL;
	pe->crc = 0;
	pe->size_of_image = 0;
	pe->load_ok = 0;
}

// Gets the image NT headers for the memory module.
PIMAGE_NT_HEADERS exe_get_img_nt_head(struct exe* pe)
{
	if (pe == NULL || pe->img_dos_head == NULL)
		return NULL;

	return MOVE_PTR(PIMAGE_NT_HEADERS, pe->img_dos_head, pe->img_dos_head->e_lfanew);
}

// Calculates the CRC32 for the given buffer.
unsigned int calc_crc32(unsigned int init_num, void* buf, unsigned int buf_size)
{
	unsigned int crc = 0, crc32_table[256];

	for (unsigned int i = 0; i < 256; i++) {
		crc = i << 24;

		for (int j = 0; j < 8; j++) {
			if (crc >> 31)
				crc = (crc << 1) ^ CRC32_POLY;
			else
				crc = crc << 1;
		}

		crc32_table[i] = crc;
	}

	crc = init_num;
	unsigned int count = buf_size;
	unsigned char* p = (unsigned char*)buf;

	while (count--)
		crc = (crc << 8) ^ crc32_table[(crc >> 24) ^ *p++];

	return crc;
}

#pragma endregion module_impl
