#include <windows.h>
#include "apitable.h"
#include "module.h"
#include "memory.h"

#pragma region forward_declaration

typedef struct unicode_str {
	unsigned short length;
	unsigned short maximum_length;
	const wchar_t* buf;
} unicode_str_t;

struct ldr_data_table_entry {
	LIST_ENTRY load_order_module_list;
	LIST_ENTRY memory_order_module_list;
	LIST_ENTRY init_order_module_list;
	void* base_addr;
	void* entry_point;
	unsigned long size_of_image;
	unicode_str_t full_name;
	unicode_str_t base_name;
	unsigned long flags;
	short load_count;
	short tls_index;
	LIST_ENTRY hash_table_entry;
	unsigned long timestamp;
};

struct peb_ldr_data {
	unsigned long length;
	unsigned char initialized;
	void* ss_handle;
	LIST_ENTRY load_order_module_list;
	LIST_ENTRY memory_order_module_list;
	LIST_ENTRY init_order_module_list;
};

#ifdef _WIN64

struct peb {
	unsigned char reserved_01[2];
	unsigned char being_debugged;
	unsigned char reserved_02[21];
	struct peb_ldr_data* ldr;
	void* process_params;
	unsigned char reserved_03[520];
	void* post_process_init_routine;
	unsigned char reserved_04[136];
	unsigned long session_id;
};

#else

struct peb {
	unsigned char reserved_01[2];
	unsigned char being_debugged;
	unsigned char reserved_02[1];
	void* reserved_03[2];
	struct peb_ldr_data* ldr;
	void* process_params;
	void* reserved_04[3];
	void* atl_thunk_s_list_ptr;
	void* reserved_05;
	unsigned long reserved_06;
	void* reserved_07;
	unsigned long reserved_08;
	unsigned long atl_thunk_s_list_ptr_32;
	void* reserved_09[45];
	unsigned char reserved_10[96];
	void* post_process_init_routine;
	unsigned char reserved_11[128];
	void* reserved_12[1];
	unsigned long session_id;
};

#endif

FARPROC get_fn_address(HMODULE h_module, const char* name);
HMODULE get_module_handle(const wchar_t* name);

#pragma endregion forward_declaration

#pragma region apitable_impl

struct api_table* api_table_new()
{
	wchar_t kernel_str[] = {'k', 'e', 'r', 'n' , 'e', 'l', '3', '2' ,'.' ,'d' ,'l' ,'l' , 0};
	HMODULE kernel = get_module_handle(kernel_str);
	if (!kernel)
		return NULL;

	char* get_fn_addr_str = "GetProcAddress";
	get_fn_addr_fn get_fn_addr = (get_fn_addr_fn)get_fn_address(kernel, get_fn_addr_str);
	if (!get_fn_addr)
		get_fn_addr = (get_fn_addr_fn)get_fn_address;

	char* global_alloc_str = "GlobalAlloc";
	char* global_free_str = "GlobalFree";
	global_alloc_fn global_alloc = (global_alloc_fn)get_fn_address(kernel, global_alloc_str);
	global_free_fn global_free = (global_free_fn)get_fn_address(kernel, global_free_str);
	if (!global_alloc || !global_free)
		return NULL;

	struct api_table* table = global_alloc(GPTR, sizeof(struct api_table));
	if (!table)
		return NULL;

	table->get_fn_addr = get_fn_addr;
	table->global_alloc = global_alloc;
	table->global_free = global_free;

	char* get_module_handle_str = "GetModuleHandleA";
	table->get_module_handle = get_fn_addr(kernel, get_module_handle_str);
	if (!table->get_module_handle)
		return NULL;

	char* load_lib_ascii_str = "LoadLibraryA";
	table->load_lib_ascii = get_fn_addr(kernel, load_lib_ascii_str);
	if (!table->get_module_handle)
		return NULL;

	char* virtual_alloc_str = "VirtualAlloc";
	table->virtual_alloc = get_fn_addr(kernel, virtual_alloc_str);
	if (!table->get_module_handle)
		return NULL;

	char* virtual_free_str = "VirtualFree";
	table->virtual_free = get_fn_addr(kernel, virtual_free_str);
	if (!table->get_module_handle)
		return NULL;

	char* virtual_protect_str = "VirtualProtect";
	table->virtual_protect = get_fn_addr(kernel, virtual_protect_str);
	if (!table->get_module_handle)
		return NULL;

	return table;
}


// Retrieves the address of the function specified by `name`.
FARPROC get_fn_address(HMODULE h_module, const char* name)
{
	// some input validation
	if (!h_module || !name)
		return NULL;

	PIMAGE_DOS_HEADER img_dos_head = (PIMAGE_DOS_HEADER)h_module;
	if (img_dos_head->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	PIMAGE_NT_HEADERS img_nt_head = MOVE_PTR(PIMAGE_NT_HEADERS, h_module, img_dos_head->e_lfanew);
	if (img_nt_head->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	unsigned long virtual_addr =
		img_nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (virtual_addr == 0)
		return NULL;

	PIMAGE_EXPORT_DIRECTORY img_export_dir = MOVE_PTR(PIMAGE_EXPORT_DIRECTORY, h_module,
		virtual_addr);

	unsigned long* name_table = MOVE_PTR(unsigned long*, h_module, img_export_dir->AddressOfNames);

	for (unsigned long i = 0; i < img_export_dir->NumberOfNames; i++) {
		if (!memory_strcmp_ascii(name, (char*)h_module + name_table[i])) {
			unsigned short* ordinal_table = MOVE_PTR(unsigned short*, h_module,
				img_export_dir->AddressOfNameOrdinals);
			unsigned long* addr_table = MOVE_PTR(unsigned long*, h_module,
				img_export_dir->AddressOfFunctions);

			return MOVE_PTR(void*, h_module, addr_table[ordinal_table[i]]);
		}
	}

	return NULL;
}

// Returns the entry to a module specified by `name`.
HMODULE get_module_handle(const wchar_t* name)
{
	// get the base address of PEB struct
#ifdef _WIN64
	struct peb* pe = (struct peb*)__readgsqword(0x60);
#else
	struct peb* pe = (struct peb*)__readfsdword(0x30);
#endif

	if (pe && pe->ldr) {
		// get header of the load_order_module_list
		PLIST_ENTRY module_list_head = &(pe->ldr->load_order_module_list);
		if (module_list_head->Flink != module_list_head) {
			struct ldr_data_table_entry* entry = NULL;
			PLIST_ENTRY curr = module_list_head->Flink;

			// find the entry of the fake module
			while (curr != module_list_head) {
				entry = CONTAINING_RECORD(curr, struct ldr_data_table_entry,
					load_order_module_list);

				if (memory_strcmp_win(entry->base_name.buf, name) == 0)
					return entry->base_addr;

				entry = NULL;
				curr = curr->Flink;
			}
		}
	}

	return NULL;
}

#pragma endregion apitable_impl
