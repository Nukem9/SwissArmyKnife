#include "stdafx.h"

int g_MenuHandle;
int g_PluginHandle;

HMODULE g_LocalDllHandle;

bool ApplySignatureSymbols(char *Path, duint ModuleBase);
bool ApplyDiffSymbols(char *Path, duint ModuleBase);
bool ApplyMapSymbols(char *Path, duint ModuleBase);

bool ExportDiffSymbols(char *Path, duint ModuleBase);
bool ExportMapSymbols(char *Path, duint ModuleBase);

void MenuEntryCallback(CBTYPE Type, PLUG_CB_MENUENTRY *Info)
{
	switch (Info->hEntry)
	{
	// IDALdr
	case PLUGIN_MENU_LOADSIG:
		OpenSelectionDialog("Open a signature file", "Signatures (*.sig)\0*.sig\0\0", false, ApplySignatureSymbols);
		break;

	case PLUGIN_MENU_LOADDIF:
		OpenSelectionDialog("Open a DIF file", "Diff files (*.dif)\0*.dif\0\0", false, ApplyDiffSymbols);
		break;

	case PLUGIN_MENU_LOADMAP:
		OpenSelectionDialog("Open a MAP file", "Map files (*.map)\0*.map\0\0", false, ApplyMapSymbols);
		break;

	case PLUGIN_MENU_EXPORTDIF:
		OpenSelectionDialog("Save a DIF file", "Diff files (*.dif)\0*.dif\0\0", true, ExportDiffSymbols);
		break;

	case PLUGIN_MENU_EXPORTMAP:
		OpenSelectionDialog("Save a MAP file", "Map files (*.map)\0*.map\0\0", true, ExportMapSymbols);
		break;

	// SigMake
	case PLUGIN_MENU_MAKESIG:
		OpenSigMakeDialog();
		break;

	case PLUGIN_MENU_SETTINGS:
		OpenSettingsDialog();
		break;

	case PLUGIN_MENU_ABOUT:
		MessageBoxA(GuiGetWindowHandle(), "Plugin created by Nukem.\n\nSource code at:\nhttps://bitbucket.org/Nukem9/idaldr/", "About", 0);
		break;
	}

	//
	// Update GUI
	//
	GuiUpdateAllViews();
}

DLL_EXPORT bool pluginit(PLUG_INITSTRUCT *InitStruct)
{
	InitStruct->pluginVersion = PLUGIN_VERSION;
	InitStruct->sdkVersion = PLUG_SDKVERSION;
	g_PluginHandle = InitStruct->pluginHandle;
	strcpy_s(InitStruct->pluginName, PLUGIN_NAME);

	// Add any of the callbacks
	_plugin_registercallback(g_PluginHandle, CB_MENUENTRY, (CBPLUGIN)MenuEntryCallback);

	// Update all checkbox settings
	Settings::InitIni();
	Settings::Load();
	return true;
}

DLL_EXPORT bool plugstop()
{
	// Close dialogs
	DestroySigMakeDialog();
	DestroySettingsDialog();

	// Clear the menu
	_plugin_menuclear(g_MenuHandle);

	// Remove callbacks
	_plugin_unregistercallback(g_PluginHandle, CB_MENUENTRY);
	return true;
}

DLL_EXPORT void plugsetup(PLUG_SETUPSTRUCT *SetupStruct)
{
	g_MenuHandle = SetupStruct->hMenu;

	// Initialize the menu
	// IDALdr
	int loadMenu = _plugin_menuadd(g_MenuHandle, "Load");
	_plugin_menuaddentry(loadMenu, PLUGIN_MENU_LOADSIG, "&SIG file");
	_plugin_menuaddentry(loadMenu, PLUGIN_MENU_LOADDIF, "&DIF file");
	_plugin_menuaddentry(loadMenu, PLUGIN_MENU_LOADMAP, "&MAP file");
	_plugin_menuaddentry(loadMenu, PLUGIN_MENU_LOADPEID, "&PEiD signatures");

	int exportMenu = _plugin_menuadd(g_MenuHandle, "Export");
	_plugin_menuaddentry(exportMenu, PLUGIN_MENU_EXPORTDIF, "&DIF file");
	_plugin_menuaddentry(exportMenu, PLUGIN_MENU_EXPORTMAP, "&MAP file");
	_plugin_menuaddseparator(g_MenuHandle);

	// SigMake
	_plugin_menuaddentry(g_MenuHandle, PLUGIN_MENU_MAKESIG, "&Create signature");
	_plugin_menuaddentry(g_MenuHandle, PLUGIN_MENU_SETTINGS, "&Signature options");
	_plugin_menuaddseparator(g_MenuHandle);

	// Misc
	_plugin_menuaddentry(g_MenuHandle, PLUGIN_MENU_ABOUT, "&About");
}

BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
		g_LocalDllHandle = hinstDLL;

	return TRUE;
}