#pragma once

namespace Settings
{
	extern bool TrimSignatures;
	extern bool DisableWildcards;
	extern bool ShortestSignatures;
	extern bool IncludeShortJumps;
	extern bool IncludeMemRefences;
	extern bool IncludeRelAddresses;
	extern SIGNATURE_TYPE LastType;

	void InitIni();
	void Load();
	void Save();
}
