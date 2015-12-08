#include "stdafx.h"

void Cmd_RegisterCommands()
{
	//
	// FINDCRYPT
	//
	_plugin_registercommand(g_PluginHandle, "findcrypt", [](int argc, char **argv)
	{
		// Exclude the command itself
		argc--;

		if (argc == 0)
		{
			// Scan entire memory range
			FindcryptScanAll();
			return true;
		}
		else if (argc == 2)
		{
			// Scan a specific memory range
			duint rangeStart	= DbgValFromString(argv[1]);
			duint rangeEnd		= DbgValFromString(argv[2]);

			FindcryptScanRange(rangeStart, rangeEnd);
			return true;
		}

		// Fail if the wrong number of arguments was used
		dprintf("Command requires 0 or 2 arguments only\n");
		return false;
	}, true);

	_plugin_registercommand(g_PluginHandle, "findcrypt_mod", [](int argc, char **argv)
	{
		// Scan the current module only
		FindcryptScanModule();
		return true;
	}, true);

	//
	// AES-FINDER
	//
	_plugin_registercommand(g_PluginHandle, "aesfinder", [](int argc, char **argv)
	{
		// Exclude the command itself
		argc--;

		if (argc == 0)
		{
			// Scan entire memory range
			AESFinderScanAll();
			return true;
		}
		else if (argc == 2)
		{
			// Scan a specific memory range
			duint rangeStart = DbgValFromString(argv[1]);
			duint rangeEnd = DbgValFromString(argv[2]);

			AESFinderScanRange(rangeStart, rangeEnd);
			return true;
		}

		// Fail if the wrong number of arguments was used
		dprintf("Command requires 0 or 2 arguments only\n");
		return false;
	}, true);

	_plugin_registercommand(g_PluginHandle, "aesfinder_mod", [](int argc, char **argv)
	{
		// Scan the current module only
		AESFinderScanModule();
		return true;
	}, true);
}