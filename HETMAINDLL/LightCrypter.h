#pragma once

typedef unsigned long int uint;
typedef unsigned long long int uint64;
typedef unsigned char uchar;

class LightCrypter
{
public:
	LightCrypter(uint u);
	~LightCrypter();

	void Decrypt(char* c);
	void appendHash(char* hash);

	char* PRG04();

private:
	uint key;

	uint nbMults;
	uint* mults;
	bool* mot;
	uint motPos;
	uint multsPos;

	std::string* PRG0;

	uint b64ToDec(char* b64);
	uint binToDec(uint bin);
};

