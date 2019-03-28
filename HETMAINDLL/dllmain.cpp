// dllmain.cpp : Définit le point d'entrée pour l'application DLL.
#include "stdafx.h"
#include "HETH.h"
#include "HETDPFL.h"
#include "HETMAIN.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	BOOL bExceptionHit = FALSE;
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		__try {
			_asm
			{
				pushfd
				or dword ptr[esp], 0x100
				popfd
				// Set the Trap Flag
				// Load value into EFLAGS register
				nop
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			bExceptionHit = TRUE;
		}

		if (bExceptionHit == FALSE)
		{
			exit(0);
			*((int*)NULL) = 59629;
		}

		if (!hetinternal::HETH::VerifyHash())
		{
			exit(0);
			*((int*)NULL) = 25127;
		}
		
		if (IsDebuggerPresent())
		{
			exit(0);
			*((int*)NULL) = 122;
		}
		
		hetinternal::HETDPFL::InjectDPF();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}

	return TRUE;
}

