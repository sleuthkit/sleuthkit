/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2011 Brian Carrier.  All Rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */


#include "tsk_base_i.h"

#ifdef TSK_WIN32


#include <windows.h>

static DWORD tlsIndex;

namespace tsk {

	static DWORD tlsIndex;

	class GetTlsIndex {
	public:
		GetTlsIndex() {
			tlsIndex = TlsAlloc();
		}
		~GetTlsIndex() {
			TlsFree(tlsIndex);
		}
	};

	static GetTlsIndex getTlsIndex;
}

/*
 * There's no destructor model in Win32 as with pthreads.
 * A DLLMain could do the job, but we're not a DLL.
 */
extern "C"
void *tsk_error_win32_get_per_thread_(unsigned struct_size) {
	void *ptr = TlsGetValue(tlsIndex);
	if (ptr == 0) {
		ptr = malloc(struct_size);
		memset(ptr, 0, struct_size);
		TlsSetValue(tlsIndex, ptr);
	}
	return ptr;
}

/*
 * Threads must call this on exit to avoid a leak.
*/
extern "C"
void tsk_error_win32_thread_cleanup() {
	void *ptr = TlsGetValue(tlsIndex);
	if (ptr != 0) {
		free(ptr);
		TlsSetValue(tlsIndex, 0);
	}
}


#endif /*TSK_WIN32*/
