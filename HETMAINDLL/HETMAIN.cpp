// HETMAINDLL.cpp : définit les fonctions exportées pour l'application DLL.
//

#include "stdafx.h"
#include "HETCrypto.h"
#include "HETMAIN.h"

char* het::HET::Crypt(std::string key, char* mess)
{
	hetcrypto::HETCrypto* htC = new hetcrypto::HETCrypto(key);

	return htC->Crypt(mess, true);
}
