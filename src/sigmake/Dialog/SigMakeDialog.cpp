#include "../stdafx.h"

HWND g_SigMakeDialog;

void MakeSigDialogInit(HWND hwndDlg)
{
	// Get the debugger window's selection and generate the signature
	SELECTIONDATA selection;

	if (!GuiSelectionGet(GUI_DISASSEMBLY, &selection))
		return;

	SIG_DESCRIPTOR *desc = GenerateSigFromCode(selection.start, selection.end);

	if (!desc)
		return;

	// SIG_DESCRIPTOR -> String
	char *data = nullptr;
	char *mask = nullptr;

	switch (Settings::LastType)
	{
	case SIG_CODE:	DescriptorToCode(desc, &data, &mask);	break;
	case SIG_IDA:	DescriptorToIDA(desc, &data);			break;
	case SIG_PEID:	DescriptorToPEiD(desc, &data);			break;
	case SIG_CRC:	DescriptorToCRC(desc, &data, &mask);	break;
	}

	BridgeFree(desc);

	// Set the edit box text and clean up
	if (data)
	{
		SetWindowText(GetDlgItem(hwndDlg, IDC_SIGMAKE_EDIT1), data);
		BridgeFree(data);
	}

	if (mask)
	{
		SetWindowText(GetDlgItem(hwndDlg, IDC_SIGMAKE_EDIT2), mask);
		BridgeFree(mask);
	}
}

void MakeSigDialogConvert(HWND hwndDlg, SIGNATURE_TYPE To, SIGNATURE_TYPE From)
{
	// Don't convert if destination and source types are the same
	if (To == From)
		return;

	int dataLen = GetWindowTextLength(GetDlgItem(hwndDlg, IDC_SIGMAKE_EDIT1)) + 1;
	int maskLen = GetWindowTextLength(GetDlgItem(hwndDlg, IDC_SIGMAKE_EDIT2)) + 1;

	char *data = (char *)BridgeAlloc(dataLen);
	char *mask = (char *)BridgeAlloc(maskLen);

	GetWindowText(GetDlgItem(hwndDlg, IDC_SIGMAKE_EDIT1), data, dataLen);
	GetWindowText(GetDlgItem(hwndDlg, IDC_SIGMAKE_EDIT2), mask, maskLen);

	// Convert string(s) to the incoming raw code descriptor
	SIG_DESCRIPTOR *inDesc = nullptr;

	switch (From)
	{
	case SIG_CODE:	inDesc = DescriptorFromCode(data, mask);	break;
	case SIG_IDA:	inDesc = DescriptorFromIDA(data);			break;
	case SIG_PEID:	inDesc = DescriptorFromPEiD(data);			break;
	case SIG_CRC:	inDesc = DescriptorFromCRC(data);			break;
	}

	BridgeFree(data);
	BridgeFree(mask);

	data = nullptr;
	mask = nullptr;

	// Convert raw code to destination strings
	switch (To)
	{
	case SIG_CODE:	DescriptorToCode(inDesc, &data, &mask);	break;
	case SIG_IDA:	DescriptorToIDA(inDesc, &data);			break;
	case SIG_PEID:	DescriptorToPEiD(inDesc, &data);		break;
	case SIG_CRC:	DescriptorToCRC(inDesc, &data, &mask);	break;
	}

	// Update dialog
	SetWindowText(GetDlgItem(hwndDlg, IDC_SIGMAKE_EDIT1), data ? data : "");
	SetWindowText(GetDlgItem(hwndDlg, IDC_SIGMAKE_EDIT2), mask ? mask : "");

	if (data)
		BridgeFree(data);

	if (mask)
		BridgeFree(mask);

	BridgeFree(inDesc);
}

void MakeSigDialogExecute(HWND hwndDlg)
{
	int dataLen = GetWindowTextLength(GetDlgItem(hwndDlg, IDC_SIGMAKE_EDIT1)) + 1;
	int maskLen = GetWindowTextLength(GetDlgItem(hwndDlg, IDC_SIGMAKE_EDIT2)) + 1;

	char *data = (char *)BridgeAlloc(dataLen);
	char *mask = (char *)BridgeAlloc(maskLen);

	GetWindowText(GetDlgItem(hwndDlg, IDC_SIGMAKE_EDIT1), data, dataLen);
	GetWindowText(GetDlgItem(hwndDlg, IDC_SIGMAKE_EDIT2), mask, maskLen);

	// Convert the string to a code descriptor
	SIG_DESCRIPTOR *desc = nullptr;

	switch (Settings::LastType)
	{
	case SIG_CODE:	desc = DescriptorFromCode(data, mask);	break;
	case SIG_IDA:	desc = DescriptorFromIDA(data);			break;
	case SIG_PEID:	desc = DescriptorFromPEiD(data);		break;
	case SIG_CRC:	desc = DescriptorFromCRC(data);			break;
	}

	// Scan & log it to the GUI
	std::vector<duint> results;
	PatternScan(desc, results);

	GuiReferenceDeleteAllColumns();
	GuiReferenceAddColumn(20, "Address");
	GuiReferenceAddColumn(100, "Disassembly");
	GuiReferenceSetRowCount((int)results.size());
	GuiReferenceSetProgress(0);

	int i = 0;
	for (auto& match : results)
	{
		DISASM_INSTR inst;
		DbgDisasmAt(match, &inst);

		char temp[32];
		sprintf_s(temp, "%p", (PVOID)match);

		GuiReferenceSetCellContent(i, 0, temp);
		GuiReferenceSetCellContent(i++, 1, inst.instruction);
	}

	_plugin_logprintf("Found %d references(s)\n", results.size());
	GuiReferenceSetProgress(100);
	GuiUpdateAllViews();

	BridgeFree(data);
	BridgeFree(mask);
	BridgeFree(desc);
}

INT_PTR CALLBACK MakeSigDialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
	{
		// Check if the user has any code selected
		MakeSigDialogInit(hwndDlg);

		// TODO: CRC disabled until I can find a good piece of code for it
		EnableWindow(GetDlgItem(hwndDlg, IDC_SIGMAKE_CRC), FALSE);

		// Update the initial signature type selection button
		switch (Settings::LastType)
		{
		case SIG_CODE:
			SendMessage(GetDlgItem(hwndDlg, IDC_SIGMAKE_CODE), BM_SETCHECK, BST_CHECKED, 0);
			break;

		case SIG_IDA:
			SendMessage(GetDlgItem(hwndDlg, IDC_SIGMAKE_IDA), BM_SETCHECK, BST_CHECKED, 0);
			break;

		case SIG_PEID:
			SendMessage(GetDlgItem(hwndDlg, IDC_SIGMAKE_PEID), BM_SETCHECK, BST_CHECKED, 0);
			break;

		case SIG_CRC:
			SendMessage(GetDlgItem(hwndDlg, IDC_SIGMAKE_CRC), BM_SETCHECK, BST_CHECKED, 0);
			break;
		}
	}
	break;

	case WM_CLOSE:
	{
		CLOSE_WINDOW(hwndDlg, g_SigMakeDialog);
		return TRUE;
	}
	break;

	case WM_COMMAND:
	{
		switch (LOWORD(wParam))
		{
		case IDC_SIGMAKE_SCAN:
			// Scan for the signature
			MakeSigDialogExecute(hwndDlg);

			CLOSE_WINDOW(hwndDlg, g_SigMakeDialog);
			break;

		case IDC_SIGMAKE_CANCEL:
			// Cancel button; close dialog
			CLOSE_WINDOW(hwndDlg, g_SigMakeDialog);
			break;

		case IDC_SIGMAKE_CODE:
			// Convert sig
			MakeSigDialogConvert(hwndDlg, SIG_CODE, Settings::LastType);

			// Uncheck the other radio button and update last set variable
			Settings::LastType = SIG_CODE;

			SendMessage(GetDlgItem(hwndDlg, IDC_SIGMAKE_IDA), BM_SETCHECK, BST_UNCHECKED, 0);
			SendMessage(GetDlgItem(hwndDlg, IDC_SIGMAKE_PEID), BM_SETCHECK, BST_UNCHECKED, 0);
			SendMessage(GetDlgItem(hwndDlg, IDC_SIGMAKE_CRC), BM_SETCHECK, BST_UNCHECKED, 0);
			break;

		case IDC_SIGMAKE_IDA:
			// Convert sig
			MakeSigDialogConvert(hwndDlg, SIG_IDA, Settings::LastType);

			// Uncheck the other radio button and update last set variable
			Settings::LastType = SIG_IDA;

			SendMessage(GetDlgItem(hwndDlg, IDC_SIGMAKE_CODE), BM_SETCHECK, BST_UNCHECKED, 0);
			SendMessage(GetDlgItem(hwndDlg, IDC_SIGMAKE_PEID), BM_SETCHECK, BST_UNCHECKED, 0);
			SendMessage(GetDlgItem(hwndDlg, IDC_SIGMAKE_CRC), BM_SETCHECK, BST_UNCHECKED, 0);
			break;

		case IDC_SIGMAKE_PEID:
			// Convert sig
			MakeSigDialogConvert(hwndDlg, SIG_PEID, Settings::LastType);

			// Uncheck the other radio button and update last set variable
			Settings::LastType = SIG_PEID;

			SendMessage(GetDlgItem(hwndDlg, IDC_SIGMAKE_CODE), BM_SETCHECK, BST_UNCHECKED, 0);
			SendMessage(GetDlgItem(hwndDlg, IDC_SIGMAKE_IDA), BM_SETCHECK, BST_UNCHECKED, 0);
			SendMessage(GetDlgItem(hwndDlg, IDC_SIGMAKE_CRC), BM_SETCHECK, BST_UNCHECKED, 0);
			break;

		case IDC_SIGMAKE_CRC:
			// Convert sig
			MakeSigDialogConvert(hwndDlg, SIG_CRC, Settings::LastType);

			// Uncheck the other radio button and update last set variable
			Settings::LastType = SIG_CRC;

			SendMessage(GetDlgItem(hwndDlg, IDC_SIGMAKE_CODE), BM_SETCHECK, BST_UNCHECKED, 0);
			SendMessage(GetDlgItem(hwndDlg, IDC_SIGMAKE_PEID), BM_SETCHECK, BST_UNCHECKED, 0);
			SendMessage(GetDlgItem(hwndDlg, IDC_SIGMAKE_IDA), BM_SETCHECK, BST_UNCHECKED, 0);
			break;
		}
	}
	break;
	}

	return FALSE;
}

void OpenSigMakeDialog()
{
	if (!DbgIsDebugging())
	{
		_plugin_logprintf("No process is being debugged!\n");
		return;
	}

	g_SigMakeDialog = CreateDialog(g_LocalDllHandle, MAKEINTRESOURCE(IDD_MAKESIG), GuiGetWindowHandle(), MakeSigDialogProc);

	if (!g_SigMakeDialog)
	{
		_plugin_logprintf("Failed to create signature view window\n");
		return;
	}

	ShowWindow(g_SigMakeDialog, SW_SHOW);
}

void DestroySigMakeDialog()
{
	if (g_SigMakeDialog)
		SendMessage(g_SigMakeDialog, WM_CLOSE, 0, 0);
}