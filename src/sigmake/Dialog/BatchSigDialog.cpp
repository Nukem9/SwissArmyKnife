#include <algorithm>
#include <execution>
#include <ctype.h>
#include "../stdafx.h"

HWND g_BatchSigDialog;

void BatchSigDialogInit(HWND hwndDlg)
{
	const char *message =
		"//\r\n"
		"// Enter a separate address on each line. Addresses must be within a module. Commented lines will be ignored. Example format:\r\n"
		"// 0x12345678\r\n"
		"// 0x0987654312345678\r\n"
		"//\r\n"
		"// NOTE: This threaded scan may consume a large amount of memory depending on module size.\r\n"
		"//\r\n";

	SetWindowText(GetDlgItem(hwndDlg, IDC_SIGMAKE_EDIT1), message);
}

void BatchSigDialogExecute(HWND hwndDlg)
{
	int dataLen = GetWindowTextLength(GetDlgItem(hwndDlg, IDC_SIGMAKE_EDIT1)) + 1;
	char *data = (char *)BridgeAlloc(dataLen);
	GetWindowText(GetDlgItem(hwndDlg, IDC_SIGMAKE_EDIT1), data, dataLen);

	// Each line will have a single hexadecimal address with a 0x prefix
	std::vector<duint> addresses;

	auto skipLine = [](const char *&Ptr)
	{
		while (Ptr[0] != '\0' && Ptr[0] != '\n')
			Ptr++;

		if (Ptr[0] == '\n')
			Ptr++;
	};

	for (const char *ptr = data; ptr[0] != '\0';)
	{
		if (ptr[0] == '/' && ptr[1] == '/')
		{
			skipLine(ptr);
			continue;
		}

		if (isspace(ptr[0]))
		{
			ptr++;
			continue;
		}

		if (ptr[0] == '0' && ptr[1] == 'x')
		{
			addresses.push_back(strtoull(&ptr[2], nullptr, 16));
			skipLine(ptr);

			continue;
		}

		_plugin_logprintf("Trying to parse malformed data in address list\n");
		break;
	}

	BridgeFree(data);

	if (addresses.empty())
	{
		_plugin_logprintf("Found no addresses to scan for\n");
		return;
	}

	_plugin_logprintf("Parsed %d addresses in list, scanning...\n", addresses.size());

	// Guess the amount of bytes needed for a unique signature starting from 10 and maxing out at ~50. This
	// doesn't take function boundaries into account.
	std::mutex descriptorLock;
	std::map<duint, SIG_DESCRIPTOR *> descriptors;

	// Avoid a lock just to assign null descriptors
	for (duint address : addresses)
		descriptors.emplace(address, nullptr);

	std::for_each(std::execution::par_unseq, addresses.begin(), addresses.end(),
	[&descriptorLock, &descriptors](duint Address)
	{
		const uint32_t minSigLength = 10;
		const uint32_t maxSigLength = 50;

		// Keep a copy of the module in memory
		duint moduleBase = DbgFunctions()->ModBaseFromAddr(Address);
		duint moduleSize = DbgFunctions()->ModSizeFromAddr(moduleBase);
		PBYTE processMemory = (PBYTE)BridgeAlloc(moduleSize);

		if (!DbgMemRead(moduleBase, processMemory, moduleSize))
		{
			_plugin_logprintf("Couldn't read process memory for address 0x%llX\n", Address);
			return;
		}

		for (uint32_t length = 0; length < maxSigLength;)
		{
			// Gather some instructions to meet the minimum length
			while (length < minSigLength)
			{
				DISASM_INSTR inst;
				DbgDisasmAt(Address + length, &inst);

				// Default to 1 byte on failure
				length += max(inst.instr_size, 1);
			}

			SIG_DESCRIPTOR *desc = GenerateSigFromCode(Address, Address + length);

			std::vector<duint> results;
			PatternScan(desc, results, moduleBase, moduleSize, processMemory);

			if (results.empty())
			{
				BridgeFree(desc);

				_plugin_logprintf("Unable to match any signatures for address 0x%llX. How did this happen?\n", Address);
				break;
			}

			if (results.size() > 1)
			{
				BridgeFree(desc);

				// Multiple results. Disassemble yet another instruction.
				DISASM_INSTR inst;
				DbgDisasmAt(Address + length, &inst);

				length += max(inst.instr_size, 1);
			}
			else
			{
				// Done.
				descriptorLock.lock();
				descriptors.insert_or_assign(Address, desc);
				descriptorLock.unlock();

				break;
			}
		}

		BridgeFree(processMemory);
	});

	// Print out all of the results
	for (auto& [address, desc] : descriptors)
	{
		char *data = nullptr;
		char *mask = nullptr;

		if (desc)
		{
			switch (Settings::LastType)
			{
			case SIG_CODE:
				DescriptorToCode(desc, &data, &mask);
				_plugin_logprintf("0x%llX: %s, %s\n", address, data, mask);
				break;

			case SIG_IDA:
				DescriptorToIDA(desc, &data);
				_plugin_logprintf("0x%llX: %s\n", address, data);
				break;

			case SIG_PEID:
				DescriptorToPEiD(desc, &data);
				_plugin_logprintf("0x%llX: %s\n", address, data);
				break;

			case SIG_CRC:
				break;
			}
		}
		else
		{
			_plugin_logprintf("0x%llX: Unable to find a valid signature for given length\n", address);
		}

		if (data)
			BridgeFree(data);

		if (mask)
			BridgeFree(mask);

		if (desc)
			BridgeFree(desc);
	}
}

INT_PTR CALLBACK BatchSigDialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
	{
		// Check if the user has any code selected
		BatchSigDialogInit(hwndDlg);

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
		CLOSE_WINDOW(hwndDlg, g_BatchSigDialog);
		return TRUE;
	}
	break;

	case WM_COMMAND:
	{
		switch (LOWORD(wParam))
		{
		case IDC_SIGMAKE_SCAN:
			// Scan for the signatures
			BatchSigDialogExecute(hwndDlg);

			CLOSE_WINDOW(hwndDlg, g_BatchSigDialog);
			break;

		case IDC_SIGMAKE_CANCEL:
			// Cancel button; close dialog
			CLOSE_WINDOW(hwndDlg, g_BatchSigDialog);
			break;

		case IDC_SIGMAKE_CODE:
			// Uncheck the other radio button and update last set variable
			Settings::LastType = SIG_CODE;

			SendMessage(GetDlgItem(hwndDlg, IDC_SIGMAKE_IDA), BM_SETCHECK, BST_UNCHECKED, 0);
			SendMessage(GetDlgItem(hwndDlg, IDC_SIGMAKE_PEID), BM_SETCHECK, BST_UNCHECKED, 0);
			SendMessage(GetDlgItem(hwndDlg, IDC_SIGMAKE_CRC), BM_SETCHECK, BST_UNCHECKED, 0);
			break;

		case IDC_SIGMAKE_IDA:
			// Uncheck the other radio button and update last set variable
			Settings::LastType = SIG_IDA;

			SendMessage(GetDlgItem(hwndDlg, IDC_SIGMAKE_CODE), BM_SETCHECK, BST_UNCHECKED, 0);
			SendMessage(GetDlgItem(hwndDlg, IDC_SIGMAKE_PEID), BM_SETCHECK, BST_UNCHECKED, 0);
			SendMessage(GetDlgItem(hwndDlg, IDC_SIGMAKE_CRC), BM_SETCHECK, BST_UNCHECKED, 0);
			break;

		case IDC_SIGMAKE_PEID:
			// Uncheck the other radio button and update last set variable
			Settings::LastType = SIG_PEID;

			SendMessage(GetDlgItem(hwndDlg, IDC_SIGMAKE_CODE), BM_SETCHECK, BST_UNCHECKED, 0);
			SendMessage(GetDlgItem(hwndDlg, IDC_SIGMAKE_IDA), BM_SETCHECK, BST_UNCHECKED, 0);
			SendMessage(GetDlgItem(hwndDlg, IDC_SIGMAKE_CRC), BM_SETCHECK, BST_UNCHECKED, 0);
			break;

		case IDC_SIGMAKE_CRC:
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

void OpenBatchSigDialog()
{
	if (!DbgIsDebugging())
	{
		_plugin_logprintf("No process is being debugged!\n");
		return;
	}

	g_BatchSigDialog = CreateDialog(g_LocalDllHandle, MAKEINTRESOURCE(IDD_BATCHSIG), GuiGetWindowHandle(), BatchSigDialogProc);

	if (!g_BatchSigDialog)
	{
		_plugin_logprintf("Failed to create signature view window\n");
		return;
	}

	ShowWindow(g_BatchSigDialog, SW_SHOW);
}

void DestroyBatchSigDialog()
{
	if (g_BatchSigDialog)
		SendMessage(g_BatchSigDialog, WM_CLOSE, 0, 0);
}