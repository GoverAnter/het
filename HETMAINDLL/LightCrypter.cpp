#include "stdafx.h"
#include "LightCrypter.h"

char* LightCrypter::PRG04()
{
	char* jd = new char[PRG0->length()+1];

	for (int i = 0; i < PRG0->length(); i++)
		jd[i] = PRG0->at(i);

	jd[PRG0->length()] = '\0';
	return jd;
}

LightCrypter::LightCrypter(uint u)
{
	PRG0 = new std::string("");
	key = u;
	srand(u);

	nbMults = rand() % (16 - 8) + 8;
	mults = new uint[nbMults]();
	for (uint i = 0; i < nbMults; i++)
		mults[i] = rand() % (315 - 127) + 127;

	uint nbrT = 0, nbrF = 0;
	mot = new bool[8]();
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
	}

	motPos = 0;
	multsPos = 0;
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
		res += nbr*(pow(base, strlen(b64) - (i + 1)));
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
	if(!mot[motPos])
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
		PRG0->append(1, (binToDec(b64ToDec(c) / mults[multsPos])));

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
