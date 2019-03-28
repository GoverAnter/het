// HETCLI.cpp : définit le point d'entrée pour l'application console.
//

#include "stdafx.h"
#include <iostream>
#include <string>
#include <vector>

std::vector<std::string> split(std::string str, std::string sep) {
	char* cstr = const_cast<char*>(str.c_str());
	char* current;
	std::vector<std::string> arr;
	current = strtok(cstr, sep.c_str());
	while (current != NULL) {
		arr.push_back(current);
		current = strtok(NULL, sep.c_str());
	}
	return arr;
}

int main(int argc, char** argv)
{
	while (true)
	{
		std::string mess;
		std::getline(std::cin, mess);
		
		std::vector<std::string> arr;
		arr = split(mess, " ");

		char* m = new char[arr.at(1).length()];
		strcpy(m, arr.at(1).c_str());

		if (mess == "stop" || mess == "quit" || mess == "exit")
			break;
		else
			printf("%s\n", het::HET::Crypt(arr.at(0), m));

		system("pause");
	}

    return 0;
}

