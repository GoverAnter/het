// HETDPFP.cpp : définit le point d'entrée pour l'application console.
//

#include "stdafx.h"
#include "HETh.h"
#include "time.h"

#include <tlhelp32.h>

DWORD getppid()
{
	HANDLE hSnapshot;
	PROCESSENTRY32 pe32;
	DWORD ppid = 0, pid = GetCurrentProcessId();

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	__try {
		if (hSnapshot == INVALID_HANDLE_VALUE) __leave;

		ZeroMemory(&pe32, sizeof(pe32));
		pe32.dwSize = sizeof(pe32);
		if (!Process32First(hSnapshot, &pe32)) __leave;

		do {
			if (pe32.th32ProcessID == pid) {
				ppid = pe32.th32ParentProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &pe32));

	}
	__finally {
		if (hSnapshot != INVALID_HANDLE_VALUE) CloseHandle(hSnapshot);
	}
	return ppid;
}

int main()
{
	srand(time(0));
	if (!hetdpfpinternal::HETh::VerifyHash())
		return rand()%2000;

	bool dbgpres = false;
	if(CheckRemoteDebuggerPresent(OpenProcess(SYNCHRONIZE, true, getppid()), (PBOOL)dbgpres))
		if(dbgpres)
			return rand() % 2000;
	
	SYSTEM_INFO sInfo;
	GetSystemInfo(&sInfo);
	TCHAR infoBuf[32767] = { 0 };
	DWORD bufCharCount = 32767;
	GetComputerName(infoBuf, &bufCharCount);

	int pKey = 0;

	for (int i = 0; i < 32767; i++)
	{
		if (infoBuf[i] == 0 || infoBuf[i] == -1)
		{
			pKey -= (i ^ (sInfo.dwNumberOfProcessors/4)) - i;
			break;
		}
		
		pKey = (pKey*i) + (infoBuf[i] ^ (i % 4));
	}

	pKey = abs(pKey);

    return pKey;
}

