#pragma once

#ifdef HETMAINDLL_EXPORTS
#define HETMAINDLL_API __declspec(dllexport)
#else
#define HETMAINDLL_API __declspec(dllimport)
#endif

namespace het
{
	class HET
	{
	public:
		static HETMAINDLL_API char* __stdcall Crypt(std::string key, char* mess);
	};
}