#pragma once
#include <string>
typedef unsigned long int uint;
typedef unsigned long long int uint64;
typedef unsigned char uchar;

class LightCrypter
{
public:
	LightCrypter(uint u);
	~LightCrypter();

	std::string Crypt(uchar c);
	void Decrypt(char* c);
	void appendHash(char* hash);

	inline const char* PRG04() { return PRG0->c_str(); }

private:
	uint key;

	uint nbMults;
	uint* mults;
	bool* mot;
	uint motPos;
	uint multsPos;

	std::string* PRG0;

	char* decTob64(uint dec);
	uint b64ToDec(char* b64);
	uint decToBin(uint dec);
	uint binToDec(uint bin);
};

