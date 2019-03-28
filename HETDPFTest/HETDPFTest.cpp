// HETDPFTest.cpp : définit le point d'entrée pour l'application console.
//

#include "stdafx.h"
#include "LightCrypter.h"
#include <iostream>

int main()
{
	LightCrypter *lc = new LightCrypter(1160572);

	std::cout << (char)97 << std::endl;
	std::string n = lc->Crypt(97);
	std::cout << n << std::endl;
	char* nn = _strdup(n.c_str());
	lc->Decrypt(nn);
	std::cout << (int)(lc->PRG04()[0]) << std::endl;

	system("pause");

    return 0;
}

