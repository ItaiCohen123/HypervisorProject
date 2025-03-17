#include <ntddk.h>
#include "VMX.h"



NTSTATUS
LogMessage(LPCSTR fileName, LPCSTR msg) {


	UNICODE_STRING fileNameW;
	ANSI_STRING ansiName;

	RtlInitAnsiString(&ansiName, fileName);
	RtlAnsiStringToUnicodeString(&fileNameW, &ansiName, TRUE); // Allocate memory

	
	HANDLE hFile;
	OBJECT_ATTRIBUTES objAttr;
	IO_STATUS_BLOCK ioStatus;

	InitializeObjectAttributes(&objAttr, &fileNameW, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	NTSTATUS result = ZwCreateFile(&hFile, GENERIC_WRITE | GENERIC_READ, &objAttr, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

	if (!NT_SUCCESS(result)) {
		DbgPrint("[*] create file failed");
		return result;
	}

	result = ZwWriteFile(hFile, NULL, NULL, NULL, &ioStatus, (PVOID)msg, sizeof(msg), NULL, NULL);

	if (!NT_SUCCESS(result)) {
		DbgPrint("[*] write file failed");
		ZwClose(hFile);
		return result;
	}


	ZwClose(hFile);
	return STATUS_SUCCESS;
}




