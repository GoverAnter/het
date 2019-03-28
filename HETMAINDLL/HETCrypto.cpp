#include "stdafx.h"
#include "HETH.h"
#include "HETDPFL.h"
#include "HETCrypto.h"

int hetcrypto::HETCrypto::PrivateKey = 0;

bool hetcrypto::HETCrypto::VerifyKey()
{
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
			pKey -= (i ^ (sInfo.dwNumberOfProcessors / 4)) - i;
			break;
		}

		pKey = (pKey*i) + (infoBuf[i] ^ (i % 4));
	}

	pKey = abs(pKey);

	return pKey == PrivateKey;
}

char* hetcrypto::HETCrypto::decTob64(uint64 dec)
{
	uint64 base = 64, nnbr = dec;
	char* res = new char[11]();

	for (int i = 9; i > 0; i--)
	{
		uint64 cpow = static_cast<uint64>(pow(base, i));
		
		if (nnbr >= cpow)
		{
			uint64 t = nnbr/cpow;
			nnbr -= cpow*(nnbr / cpow);

			if (t < 10)
				res[9 - i] = (char)(t+48);
			else if (t == 10)
				res[9 - i] = (char)43;
			else if (t == 37)
				res[9 - i] = (char)61;
			else if (t > 10 && t < 37)
				res[9 - i] = (char)(97 + (t - 11));
			else if (t > 37)
				res[9 - i] = (char)(65 + (t - 38));
		}
		else
			res[9 - i] = (char)48;
	}

	res[10] = '\0';

	return res;
}

//TODO add security if b64 invalid
uint64 hetcrypto::HETCrypto::b64ToDec(char* b64)
{
	uint64 res = 0, base = 64;

	for (uint64 i = 0; i < strlen(b64); i++)
	{
		uint64 nbr;

		if (b64[i] >= '0' && b64[i] <= '9')
			nbr = '0' - b64[i];
		else if (b64[i] == '+')
			nbr = 10;
		else if (b64[i] == '=')
			nbr = 37;
		else if (b64[i] >= 'a' && b64[i] <= 'z')
			nbr = 11 + ('a' - b64[i]);
		else if (b64[i] >= 'A' && b64[i] <= 'Z')
			nbr = 38 + ('A' - b64[i]);

		res += nbr*static_cast<uint64>(pow(base, i));
	}

	return res;
}

uint64 hetcrypto::HETCrypto::decToBin(uint dec)
{
	uint nbr = dec, base = 2;
	uint64 res = 0, ten = 10;

	for (int q = 15; q >= 0; q--)
	{
		uint cpow = static_cast<uint>(pow(base, q));
		if (nbr >= cpow)
		{
			nbr -= cpow;
			res += static_cast<uint64>(pow(ten, q));
		}
	}

	return res;
}

uint hetcrypto::HETCrypto::binToDec(uint64 bin)
{
	uint64 nbr = bin, ten = 10;
	uint base = 2, res = 0;

	for (int i = 15; i >= 0; i--)
	{
		uint64 cpow = static_cast<uint64>(pow(ten, i));

		if (nbr >= cpow)
		{
			nbr -= cpow;
			res += (uint)pow(base , i);
		}
	}

	return res;
}

void hetcrypto::HETCrypto::append(char* txt)
{
	if (strlen(txt) + strlen(cumulatedResult) + 2 > crSize)
	{
		crSize += 4 * strlen(txt);
		char* nchar = new char[crSize]();
		nchar = strncpy(nchar, cumulatedResult, strlen(cumulatedResult));
		cumulatedResult = nchar;
	}

	uint lindex = strlen(cumulatedResult);
	for (uint i = (lindex==0?1:0); i < strlen(txt) + 1; i++)
	{
		if (i == 0 && lindex != 0)
			cumulatedResult[i + lindex] = '\x20';
		else
			cumulatedResult[(lindex == 0 ? i - 1:i) + lindex] = txt[i - 1];
	}

	cumulatedResult[strlen(txt) + 1 + lindex] = '\0';
}

hetcrypto::HETCrypto::HETCrypto(std::string key)
{
	if (IsDebuggerPresent())
	{
		exit(0);
		*((int*)NULL) = 26522;
	}
	
	if (PrivateKey == 0)
	{
		if (!hetinternal::HETH::VerifyHash())
		{
			exit(0);
			*((int*)NULL) = 9047;
		}

		hetinternal::HETDPFL::InjectDPF();
	}

	if (!VerifyKey())
	{
		exit(0);
		*((int*)NULL) = 698;
	}

	cookedKey = 0;

	if (key.length() == 0)
		return;

	initDone = false;

	uint lchar = 97 + (key.length()%14) + (key[0]%14);
	for (uint i = 0; i < key.length(); i++)
	{
		if (key[i] < 97 || key[i] > 122)
		{
			key[i] = (key[i] % (122 - lchar + 1)) + lchar;
			lchar++;
			if (lchar >= 120)
				lchar = 97;
		}
	}

	if (key.length() > 32)
	{
		int lindex = 0;
		for (uint i = 32; i < key.length(); i++)
		{
			key[lindex] = (key[lindex] + key[i]) / 2;

			lindex++;

			if (lindex == 32)
				lindex = 0;
		}
	}
	else if (key.length() < 32)
	{
		int l = key.length();
		for (int i = 0; i < 32 - l; i++)
		{
			if (lchar >= 119)
				lchar = 97 + (lchar%5);
			key += (char)lchar;
			lchar += key[i]%6;
		}
	}

	char* nkey = new char[32]();
	key.copy(nkey, 32, 0);

	origKey = nkey;
	uint size = 32, fct = (key[0]%4)+1, offset = 0, cKey = 0;

	while (offset < size)
	{
		uint current = 0;

		for (uint i = 0; i < 8; i++)
		{
			if (offset + i == size)
			{
				offset = size;
				break;
			}
			
			current += (static_cast<uint>(pow((key[i + offset] - 50), fct))) + (offset * (key[i + offset] - 50));
		}
		
		cKey += (current*fct)/(offset/2==0?1:offset/2);
		
		offset += 8;
	}

	if(cKey < 100000)
		cKey = static_cast<uint>(pow((cKey / fct), 2));

	cookedKey = cKey;

	if (!VerifyKey())
	{
		exit(0);
		*((int*)NULL) = 5201;
	}
}

float hetcrypto::HETCrypto::pNoise(float x, float y)
{
	int n = static_cast<int>(x + y * 57);
	n = (n << 13) ^ n;
	return (1.0f - ((n * ((n * n * 15731) + 789221) + 1376312589) & 0x7fffffff) / 1073741824.0f);
}

float hetcrypto::HETCrypto::pTwo(float x, float y, float gain, int octaves, int hgrid)
{
	float total = 0.0f;
	float frequency = 1.0f / (float)hgrid;
	float amplitude = gain;
	float lacunarity = 2.0f;

	for (int i = 0; i < octaves; ++i)
	{
		total += pNoise((float)x * frequency, (float)y * frequency) * amplitude;
		frequency *= lacunarity;
		amplitude *= gain;
	}

	return (total);
}

char* hetcrypto::HETCrypto::Crypt(char* message, bool reinit)
{
	if (IsDebuggerPresent())
	{
		exit(0);
		*((int*)NULL) = 1024;
	}

	if (strlen(message) == 0 || cookedKey == 0)
		return NULL;

	if (!initDone || reinit)
	{
		//init rand gen to get mults values
		srand((uint)floor(pTwo(sqrtf(cookedKey/4.f), cookedKey / 2.0f, pNoise(cookedKey / 100.f, cookedKey / 200.f), (cookedKey % 5) + 1, (cookedKey % 4) + 1))*(cookedKey / 10));
		nbMults = rand() % (19 - 13) + 13;
		mults = new uint64[nbMults]();
		for (uint i = 0; i < nbMults; i++)
			mults[i] = rand() % (600 - 152) + 152;

		//init rand gen to get mot values
		srand((uint)floor(pTwo(cookedKey / 2.0f, sqrtf(cookedKey/2.f), pNoise(cookedKey / 200.f, cookedKey / 100.f), (cookedKey % 4) + 1, (cookedKey % 5) + 1))*(cookedKey / 20));
		uint nbrT = 0, nbrF = 0;
		mot = new bool[8]();
		for (int i = 0; i < 8; i++)
		{
			if(i < 4)
				mot[i] = (rand() % 2)!=0;
			else if(i < 7) //force to get equal repartition
			{
				if (nbrF == nbrT)
					mot[i] = (rand() % 2)!=0;
				else if (nbrT < nbrF)
					mot[i] = 1;
				else
					mot[i] = 0;
			}
			else //enforce last to get equal repartition
			{
				if (nbrT < nbrF)
					mot[i] = 1;
				else
					mot[i] = 0;
			}

			if (mot[i] == 1)
				nbrT++;
			else
				nbrF++;
		}

		//init rand gen to get motNbr values
		srand((uint)floor(pTwo(sqrtf(cookedKey / 5.f), cookedKey / 3.0f, pNoise(cookedKey / 300.f, cookedKey / 150.f), (cookedKey % 5) + 1, (cookedKey % 4) + 1))*(cookedKey / 30));
		motNbr = new uint[8]();
		for (int i = 0; i < 8; i++)
			motNbr[i] = rand() % (9 - 3) + 3;

		//init rand gen to get crypt rand values later
		srand((uint)floor(pTwo(cookedKey / 3.0f, sqrtf(cookedKey / 5.f), pNoise(cookedKey / 150.f, cookedKey / 300.f), (cookedKey % 3) + 1, (cookedKey % 5) + 1))*(cookedKey / 30));

		motPos = 0;
		multsPos = 0;
		crSize = strlen(message)*8;

		cumulatedResult = new char[crSize]();
		cumulatedResult[0] = 0;
	}
	
	uint mLength = strlen(message);

	for (uint i = 0; i < mLength; i++)
	{
		uchar cl = message[i];

		while(!mot[motPos])
		{
			for (uint z = 0; z < motNbr[motPos]; z++)
			{
				append(decTob64(decToBin(rand() % (65109 - 34652) + 34652)*mults[multsPos]));
				
				if (multsPos == nbMults-1)
					multsPos = 0;
				else
					multsPos++;
			}


			if (motPos == 7)
				motPos = 0;
			else
				motPos++;
		}
		
		for (uint z = 0; z < motNbr[motPos]; z++)
		{
			append(decTob64(decToBin((static_cast<uint64>(pow(cl, (abs((int)(pTwo(static_cast<float>(cookedKey/cl), static_cast<float>(cookedKey/(cl*2)), sqrtf(cl)/(cl*4), static_cast<int>(floorf(sqrtf(cl) / (cl * 4))), 2))))))) % (65109 - 34652) + 34652)*mults[multsPos]));
			
			if (multsPos == nbMults - 1)
				multsPos = 0;
			else
				multsPos++;
		}

		if (motPos == 7)
			motPos = 0;
		else
			motPos++;
	}

	return cumulatedResult;
}