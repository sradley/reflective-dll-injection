#include <windows.h>
#include "injector.h"
#include "module.h"
#include "apitable.h"
#include "memory.h"

#pragma region injector_impl

exe_handle_t exe_handle_new(void* exe_buf, int call_entry, int* error)
{
	struct api_table *api = api_table_new();
	if (!api) {
		if (error)
			*error = (int)EXE_INVALID_WIN32_ENV;
		return NULL;
	}

	struct exe* exe = api->global_alloc(GPTR, sizeof(struct exe));
	if (!exe) {
		if (error)
			*error = (int)EXE_INVALID_WIN32_ENV;
		return NULL;
	}

	exe->api = api;
	exe->call_entry = call_entry;
	exe->load_ok = FALSE;
	exe->error_code = EXE_OK;

	if (exe_init(exe, exe_buf)) {
		if (error)
			*error = 0;
		return (exe_handle_t)exe;
	}

	if (error)
		*error = (int)exe->error_code;

	api->global_free(exe);
	api->global_free(api);

	return NULL;
}

int exe_handle_main(exe_handle_t exe) {
	if (!exe_call_entry(exe, DLL_PROCESS_ATTACH)) {
		// failed to call entry point, so clean resource and return false
		exe_unmap(exe);
		return 0;
	}

	return 1;
}

FARPROC exe_handle_get_fn(exe_handle_t exe_handle, const char* name)
{
	return exe_get_fn((struct exe*)exe_handle, name);
}

void exe_handle_free(exe_handle_t exe_handle)
{
	struct exe *exe = (struct exe*)exe_handle;
	exe_free(exe);

	if (exe) {
		global_free_fn global_free = exe->api->global_free;

		if (global_free) {
			global_free(exe->api);
			global_free(exe);
		}
	}
}

#pragma endregion injector_impl