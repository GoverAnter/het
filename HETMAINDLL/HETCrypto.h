#pragma once

typedef unsigned long int uint;
typedef unsigned long long int uint64;
typedef unsigned char uchar;

namespace hetcrypto
{
	class HETCrypto
	{
	public:
		//Constructors
		HETCrypto(std::string key);

		//Methods
		char* Crypt(char* message, bool reinit);

		//Static members
		static int PrivateKey;
	private:
		//Members
		char* origKey;
		uint cookedKey;

		bool initDone;

		//Crypt members
		uint nbMults;
		uint64* mults;
		bool* mot;
		uint* motNbr;
		uint motPos;
		uint multsPos;
		char* cumulatedResult;
		uint crSize;

		//Methods
		bool VerifyKey();
		char* decTob64(uint64 dec);
		uint64 b64ToDec(char* b64);
		uint64 decToBin(uint dec);
		uint binToDec(uint64 bin);
		void append(char* txt);

		float pNoise(float x, float y);
		float pTwo(float x, float y, float gain, int octaves, int hgrid);
	};
}

