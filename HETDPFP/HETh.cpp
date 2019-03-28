#include "stdafx.h"
#include "HETh.h"


bool hetdpfpinternal::HETh::VerifyHash()
{
	FILE* f = fopen("HETMain.dll", "rb");

	fseek(f, 0, SEEK_END);
	unsigned long size = ftell(f);
	fseek(f, 0, SEEK_SET);

	char* buffer = (char*)malloc(sizeof(char)*size);
	int begpos = 0, npos = 0; bool found = false, bfound = false;
	char HashMessagePayload[193] = { 0 };
	char HashString[65] = { 0 };

	if (fread(buffer, 1, size, f) == size)
	{
		fclose(f);
		int n = 0;
		for (int i = 0; i < size; i++)
		{
			if (buffer[i] == RS001[n])
			{
				++n;

				if (n == 1 && !bfound)
					begpos = i;
				else if (n == 1)
					npos = i;
			}
			else if (n != 0)
				n = 0;

			if (n == 64)
			{
				if (npos != 0)
				{
					found = true;
					break;
				}
				else
				{
					n = 0;
					bfound = true;
				}
			}
		}

		if (!found)
			return 1;

		BYTE* hash04 = new BYTE[size - 132]();

		for (int i = 0; i < begpos; i++)
			hash04[i] = 'A' + ((unsigned char)buffer[i] % 20);

		for (int i = begpos; i < npos; i++)
			hash04[i] = 'A' + ((unsigned char)buffer[i + 64] % 20);

		for (int i = 0; i < size - npos - 64; i++)
			hash04[i + begpos + (npos - begpos - 64)] = 'A' + ((unsigned char)buffer[i + npos + 64] % 20);

		hash04[size - 133] = '\0';

		HCRYPTPROV hcp;
		HCRYPTHASH hhash;

		if (CryptAcquireContext(&hcp, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
		{
			if (CryptCreateHash(hcp, CALG_SHA_256, 0, 0, &hhash))
			{
				if (CryptHashData(hhash, hash04, size - 132, 0))
				{
					BYTE HashBytes[32] = { 0 };
					DWORD HashSize = 32;

					if (CryptGetHashParam(hhash, HP_HASHVAL, HashBytes, &HashSize, 0))
					{
						char *Hex = "0123456789abcdef";

						for (int Count = 0; Count < 32; Count++)
						{
							HashString[Count * 2] = Hex[HashBytes[Count] >> 4];
							HashString[(Count * 2) + 1] = Hex[HashBytes[Count] & 0xF];
						}

						free(hash04);

						if (strcmp(HashString, RS001) != 0)
							return false;
						else
							return true;
					}
				}
				CryptDestroyHash(hhash);
			}
			CryptReleaseContext(hcp, 0);
		}
	}

	fclose(f);
	return false;
}