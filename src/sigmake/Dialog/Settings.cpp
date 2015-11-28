#include "../stdafx.h"

namespace Settings
{
	char IniPath[MAX_PATH];

	bool TrimSignatures;
	bool DisableWildcards;
	bool ShortestSignatures;
	bool IncludeShortJumps;
	bool IncludeMemRefences;
	bool IncludeRelAddresses;
	SIGNATURE_TYPE LastType;

	void InitIni()
	{
		// Get the current directory
		GetCurrentDirectory(ARRAYSIZE(IniPath), IniPath);

		// Append the file name
		strcat_s(IniPath, "\\sigmake_options.ini");

		// Create the file if it doesn't exist
		HANDLE file = CreateFile(IniPath, GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);

		if (file != INVALID_HANDLE_VALUE)
		{
			// The file was created
			CloseHandle(file);

			// Set the default values
			TrimSignatures		= true;
			IncludeShortJumps	= true;
			IncludeRelAddresses = true;

			Save();
		}
	}

	void Load()
	{
		auto GetProfileBool = [](const char *Setting) -> bool
		{
			return GetPrivateProfileInt("Options", Setting, 0, IniPath) > 0;
		};

		TrimSignatures		= GetProfileBool("TrimSignatures");
		DisableWildcards	= GetProfileBool("DisableWildcards");
		ShortestSignatures	= GetProfileBool("ShortestSignatures");
		IncludeShortJumps	= GetProfileBool("IncludeShortJumps");
		IncludeMemRefences	= GetProfileBool("IncludeMemRefences");
		IncludeRelAddresses	= GetProfileBool("IncludeRelAddresses");
		LastType			= (SIGNATURE_TYPE)GetPrivateProfileInt("Options", "LastType", 0, IniPath);
	}

	void Save()
	{
		auto SetProfileInt = [](const char *Setting, int Value) -> void
		{
			char temp[32];
			sprintf_s(temp, "%i", (Value) ? 1 : 0);

			WritePrivateProfileString("Options", Setting, temp, IniPath);
		};

		SetProfileInt("TrimSignatures",			TrimSignatures);
		SetProfileInt("DisableWildcards",		DisableWildcards);
		SetProfileInt("ShortestSignatures",		ShortestSignatures);
		SetProfileInt("IncludeShortJumps",		IncludeShortJumps);
		SetProfileInt("IncludeMemRefences",		IncludeMemRefences);
		SetProfileInt("IncludeRelAddresses",	IncludeRelAddresses);
		SetProfileInt("LastType",				LastType);
	}
}