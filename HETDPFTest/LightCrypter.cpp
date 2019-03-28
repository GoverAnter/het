#include "stdafx.h"
#include "LightCrypter.h"

LightCrypter::LightCrypter(uint u)
{
	PRG0 = new std::string("");
	key = u;
	srand(u);

	nbMults = rand() % (16 - 8) + 8;
	mults = new uint[nbMults](); printf("mults[%u] { ", nbMults);
	for (uint i = 0; i < nbMults; i++)
	{
		if(i != 0)
			printf(", ");
		mults[i] = rand() % (315 - 127) + 127;
		printf("%i", mults[i]);
	}
	printf(" }\n");
	uint nbrT = 0, nbrF = 0;
	mot = new bool[8](); printf("mot[8] { ");
	for (int i = 0; i < 8; i++)
	{
		if (i < 4)
			mot[i] = (rand() % 2) != 0;
		else if (i < 7) //force to get equal repartition
		{
			if (nbrF == nbrT)
				mot[i] = (rand() % 2) != 0;
			else if (nbrT < nbrF)
				mot[i] = true;
			else
				mot[i] = false;
		}
		else //enforce last to get equal repartition
		{
			if (nbrT < nbrF)
				mot[i] = true;
			else
				mot[i] = false;
		}

		if (mot[i] == 1)
			nbrT++;
		else
			nbrF++;
		if (i != 0)
			printf(", ");
		printf("%i", mot[i]);
	}printf(" }\n");

	motPos = 0;
	multsPos = 0;
}

char* LightCrypter::decTob64(uint dec)
{
	uint base = 64, nnbr = dec;
	char* res = new char[7]{ '0', '0', '0', '0', '0', '0', '\0' };

	for (int i = 5; i >= 0; i--)
	{
		uint cpow = pow(base, i);

		if (nnbr >= cpow)
		{
			uint t = nnbr / cpow;
			nnbr -= cpow*(nnbr / cpow);

			if (t < 10)
				res[5 - i] = (char)(t + 48);
			else if (t == 10)
				res[5 - i] = (char)43;
			else if (t == 37)
				res[5 - i] = (char)61;
			else if (t > 10 && t < 37)
				res[5 - i] = (char)(97 + (t - 11));
			else if (t > 37)
				res[5 - i] = (char)(65 + (t - 38));
		}
		else
			res[5 - i] = (char)48;
	}

	return res;
}

//TODO add security if b64 invalid
uint LightCrypter::b64ToDec(char* b64)
{
	uint res = 0, base = 64;
	for (int i = 0; i < strlen(b64); i++)
	{
		uint nbr = 0;

		if (b64[i] >= 48 && b64[i] <= 57)
			nbr = b64[i] - 48;
		else if (b64[i] == 43)
			nbr = 10;
		else if (b64[i] == 61)
			nbr = 37;
		else if (b64[i] >= 97 && b64[i] <= 122)
			nbr = (b64[i] - 97) + 11;
		else if (b64[i] >= 65 && b64[i] <= 90)
			nbr = 38 + (b64[i] - 65);
		res += nbr*(pow(base, strlen(b64)-(i+1)));
	}

	return res;
}

uint LightCrypter::decToBin(uint dec)
{
	uint nbr = dec, base = 2;
	uint res = 0, ten = 10;

	for (int q = 7; q >= 0; q--)
	{
		uint cpow = pow(base, q);
		if (nbr >= cpow)
		{
			nbr -= cpow;
			res += pow(ten, q);
		}
	}

	return res;
}

uint LightCrypter::binToDec(uint bin)
{
	uint nbr = bin, ten = 10;
	uint base = 2, res = 0;

	for (int i = 7; i >= 0; i--)
	{
		uint cpow = pow(ten, i);

		if (nbr >= cpow)
		{
			nbr -= cpow;
			res += pow(base, i);
		}
	}
	
	return res;
}





LightCrypter::~LightCrypter()
{
	delete PRG0;
}

void LightCrypter::Decrypt(char* c)
{
	motPos = 0;
	multsPos = 0;

	if(mot[motPos] == 0)
	{
		if (multsPos == nbMults - 1)
			multsPos = 0;
		else
			multsPos++;

		if (motPos == 7)
			motPos = 0;
		else
			motPos++;
	}
	else
	{
		PRG0->append(1, (binToDec(b64ToDec(c) / mults[multsPos]) - 35));

		if (multsPos == nbMults - 1)
			multsPos = 0;
		else
			multsPos++;

		if (motPos == 7)
			motPos = 0;
		else
			motPos++;
	}
}

void LightCrypter::appendHash(char* hash)
{
	PRG0->append(hash);
}

std::string LightCrypter::Crypt(uchar c)
{
	std::string res = "";

	while (!mot[motPos])
	{
		res += decTob64(decToBin(rand() % (255 - 1) + 1)*mults[multsPos]);

		if (multsPos == nbMults - 1)
			multsPos = 0;
		else
			multsPos++;


		if (motPos == 7)
			motPos = 0;
		else
			motPos++;
	}

	res += decTob64(decToBin(c + 35)*mults[multsPos]);

	if (multsPos == nbMults - 1)
		multsPos = 0;
	else
		multsPos++;

	if (motPos == 7)
		motPos = 0;
	else
		motPos++;

	return res;
}