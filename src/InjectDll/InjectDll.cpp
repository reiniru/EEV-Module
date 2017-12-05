// InjectDll.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"


#define CREATE_THREAD_ACCESS (PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ)


void DebugMsg(std::wstring msg)
{
	DWORD msgID = GetLastError();
	LPWSTR msgbuffer = nullptr;

	if (msgID != 0)
	{

		size_t size = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, msgID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&msgbuffer, 0, NULL);

		std::wstring message(msgbuffer, size);

		std::wcout << msg << message << std::endl;

		LocalFree(msgbuffer);
	}
	else
		std::wcout << msg << std::endl;
}

HANDLE OpenProcessByName(std::wstring name)
{
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hProcess = NULL;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE && hProcess == NULL)
		{
			if (_wcsicmp(entry.szExeFile, name.c_str()) == 0)
			{
				hProcess = OpenProcess(CREATE_THREAD_ACCESS, FALSE, entry.th32ProcessID);

				

				
			}
		}
	}

	CloseHandle(snapshot);

	return hProcess;
}


int main()
{
	 char libPath[] = "D:\\Users\\NexusJ\\Documents\\Visual Studio 2017\\Projects\\Inject\\AddVictim\\x64\\Release\\PayloadDll.dll";
	DWORD hLibModule;

	DebugMsg(L"INFO: Searching for process to open...");

	HANDLE hThread = OpenProcessByName(L"Soma.exe");

	if (hThread != NULL)
	{
		DebugMsg(L"INFO: Process found and open!");

		LPVOID LoadLibrAddr = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");

		if (LoadLibrAddr == NULL)
		{
			DebugMsg(L"ERROR: Failed to find LoadLibraryW address: ");
			return -1;
		}

		DebugMsg(L"INFO: Allocation virtual memory...");

		LPVOID pLibRemote = VirtualAllocEx(hThread, NULL, sizeof(libPath), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (pLibRemote == NULL)
		{
			DebugMsg(L"ERROR: Error when allocatin virtual memory: ");
			return -1;
		}

		DebugMsg(L"INFO: writing memory to process...");

		if (!WriteProcessMemory(hThread, pLibRemote, (void*)libPath, sizeof(libPath), NULL))
		{
			DebugMsg(L"ERROR: Error when writing memory to process: ");
				return -1;
		}

		DebugMsg(L"INFO: Creating remote thread...");

		HANDLE hRmThread = CreateRemoteThread(hThread, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibrAddr, pLibRemote, 0, NULL);

		if (hRmThread == NULL)
		{
			DebugMsg(L"ERROR: Error creating remote thread in process: ");
			return -1;
		}

		DebugMsg(L"INFO: waiting thread to execute...");

		WaitForSingleObject(hRmThread, INFINITE);
		while (GetExitCodeThread(hRmThread, &hLibModule))
		{
			
				if (hLibModule != STILL_ACTIVE)
					break;
		}
		DebugMsg(L"INFO: done! Now closing handles...");
		
		//CloseHandle(hRmThread);
		CloseHandle(hThread);

		VirtualFreeEx(hThread, pLibRemote, sizeof(libPath), MEM_RELEASE);

		return true;
	}
	else
		DebugMsg(L"Error when opening process: ");

    return false;
}

