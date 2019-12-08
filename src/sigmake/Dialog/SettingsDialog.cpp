#include "../stdafx.h"

HWND g_SettingsDialog;

INT_PTR CALLBACK SettingsDialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
	{
		// If this isn't a 64-bit build, disable the RIP-relative option
#ifndef _WIN64
		EnableWindow(GetDlgItem(hwndDlg, IDC_SETTINGS_RELADDR), FALSE);
#endif // ndef _WIN64

		// Update all check box settings
		#define CHECK(x) ((x) ? BST_CHECKED : BST_UNCHECKED)
		SendMessage(GetDlgItem(hwndDlg, IDC_SETTINGS_TRIM), BM_SETCHECK, CHECK(Settings::TrimSignatures), 0);
		SendMessage(GetDlgItem(hwndDlg, IDC_SETTINGS_NOWILDCARD), BM_SETCHECK, CHECK(Settings::DisableWildcards), 0);
		SendMessage(GetDlgItem(hwndDlg, IDC_SETTINGS_SHORTEST), BM_SETCHECK, CHECK(Settings::ShortestSignatures), 0);
		SendMessage(GetDlgItem(hwndDlg, IDC_SETTINGS_SHORTJMP), BM_SETCHECK, CHECK(Settings::IncludeShortJumps), 0);
		SendMessage(GetDlgItem(hwndDlg, IDC_SETTINGS_MEMREFS), BM_SETCHECK, CHECK(Settings::IncludeMemRefences), 0);
		SendMessage(GetDlgItem(hwndDlg, IDC_SETTINGS_RELADDR), BM_SETCHECK, CHECK(Settings::IncludeRelAddresses), 0);
		SendMessage(GetDlgItem(hwndDlg, IDC_SETTINGS_USESEGMENTS), BM_SETCHECK, CHECK(Settings::UseSegments), 0);
	}
	break;

	case WM_CLOSE:
	{
		CLOSE_WINDOW(hwndDlg, g_SettingsDialog);
		return TRUE;
	}
	break;

	case WM_COMMAND:
	{
		switch (LOWORD(wParam))
		{
		case IDC_SETTINGS_OK:
			// Update each checkbox setting at once
			Settings::TrimSignatures		= SendMessage(GetDlgItem(hwndDlg, IDC_SETTINGS_TRIM), BM_GETCHECK, 0, 0) == BST_CHECKED;
			Settings::DisableWildcards		= SendMessage(GetDlgItem(hwndDlg, IDC_SETTINGS_NOWILDCARD), BM_GETCHECK, 0, 0) == BST_CHECKED;
			Settings::ShortestSignatures	= SendMessage(GetDlgItem(hwndDlg, IDC_SETTINGS_SHORTEST), BM_GETCHECK, 0, 0) == BST_CHECKED;
			Settings::IncludeShortJumps		= SendMessage(GetDlgItem(hwndDlg, IDC_SETTINGS_SHORTJMP), BM_GETCHECK, 0, 0) == BST_CHECKED;
			Settings::IncludeMemRefences	= SendMessage(GetDlgItem(hwndDlg, IDC_SETTINGS_MEMREFS), BM_GETCHECK, 0, 0) == BST_CHECKED;
			Settings::IncludeRelAddresses	= SendMessage(GetDlgItem(hwndDlg, IDC_SETTINGS_RELADDR), BM_GETCHECK, 0, 0) == BST_CHECKED;
			Settings::UseSegments           = SendMessage(GetDlgItem(hwndDlg, IDC_SETTINGS_USESEGMENTS), BM_GETCHECK, 0, 0) == BST_CHECKED;

			// Save options
			Settings::Save();

			// Close dialog
			CLOSE_WINDOW(hwndDlg, g_SettingsDialog);
			break;

		case IDC_SETTINGS_CANCEL:
			CLOSE_WINDOW(hwndDlg, g_SettingsDialog);
			break;
		}
	}
	break;
	}

	return FALSE;
}

void OpenSettingsDialog()
{
	g_SettingsDialog = CreateDialog(g_LocalDllHandle, MAKEINTRESOURCE(IDD_SETTINGS), GuiGetWindowHandle(), SettingsDialogProc);

	if (!g_SettingsDialog)
	{
		_plugin_logprintf("Failed to create settings window\n");
		return;
	}

	ShowWindow(g_SettingsDialog, SW_SHOW);
}

void DestroySettingsDialog()
{
	if (g_SettingsDialog)
		SendMessage(g_SettingsDialog, WM_CLOSE, 0, 0);
}