

#include <conio.h>
#include <iostream>
#include <vector>
#include <bitset>
#include <array>
#include <string>
#include <intrin.h>
#include <Windows.h>
#include <strsafe.h>

#define IOCTL_Device_Function CTL_CODE(DeviceType, Function, Method, Access)

//defining all the IOCTL control codes:

#define IOCTL_SIOCTL_METHOD_BUFFERED CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SIOCTL_METHOD_NEITHER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_SIOCTL_METHOD_IN_DIRECT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_IN_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_SIOCTL_METHOD_OUT_DIRECT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)


using namespace std;

std::string
GetCpuID()
{
    char   SysType[13]; // Array consisting of 13 single bytes/characters
    string CpuID;       // The string that will be used to add all the characters to
    // Starting coding in assembly language
    _asm
    {
        // Execute CPUID with EAX = 0 to get the CPU producer
        XOR EAX, EAX
        CPUID
        // MOV EBX to EAX and get the characters one by one by using shift out right bitwise operation.
        MOV EAX, EBX
        MOV SysType[0], AL
        MOV SysType[1], AH
        SHR EAX, 16
        MOV SysType[2], AL
        MOV SysType[3], AH
        // Get the second part the same way but these values are stored in EDX
        MOV EAX, EDX
        MOV SysType[4], AL
        MOV SysType[5], AH
        SHR EAX, 16
        MOV SysType[6], AL
        MOV SysType[7], AH
        // Get the third part
        MOV EAX, ECX
        MOV SysType[8], AL
        MOV SysType[9], AH
        SHR EAX, 16
        MOV SysType[10], AL
        MOV SysType[11], AH
        MOV SysType[12], 00
    }
    CpuID.assign(SysType, 12);
    return CpuID;
}



bool DetectVmxSupport() {

    int cpuinfo[4] = { 0 };
    __cpuid(cpuinfo, 1);

    bool vmxsupported = (cpuinfo[2] & (1 << 5)) != 0;

    return vmxsupported;

}

void
PrintAppearance()
{
    printf("\n"

        "    _   _                             _                  _____                      ____                 _       _     \n"
        "   | | | |_   _ _ __   ___ _ ____   _(_)___  ___  _ __  |  ___| __ ___  _ __ ___   / ___|  ___ _ __ __ _| |_ ___| |__  \n"
        "   | |_| | | | | '_ \\ / _ \\ '__\\ \\ / / / __|/ _ \\| '__| | |_ | '__/ _ \\| '_ ` _ \\  \\___ \\ / __| '__/ _` | __/ __| '_ \\ \n"
        "   |  _  | |_| | |_) |  __/ |   \\ V /| \\__ \\ (_) | |    |  _|| | | (_) | | | | | |  ___) | (__| | | (_| | || (__| | | |\n"
        "   |_| |_|\\__, | .__/ \\___|_|    \\_/ |_|___/\\___/|_|    |_|  |_|  \\___/|_| |_| |_| |____/ \\___|_|  \\__,_|\\__\\___|_| |_|\n"
        "          |___/|_|                                                                                                     \n"

        "\n\n");
}

bool
TestIOCTL(HANDLE hDriver) {

    
    ULONG BytesReturned;
    BOOL  Result;
    char  OutputBuffer[1000];
    char  InputBuffer[1000];

    //
    // Performing METHOD_BUFFERED
    //
    
    int res = strcpy_s(InputBuffer, sizeof(InputBuffer), "This String is from User Application; using METHOD_BUFFERED\n");

    if (res != 0) {
        printf("strcpy_s failed");
        return 1;
    }

    printf("\nCalling DeviceIoControl METHOD_BUFFERED:\n");

    memset(OutputBuffer, 0, sizeof(OutputBuffer));

    // calling DeviceIOControl for communication with driver
    Result = DeviceIoControl(hDriver,
        (DWORD)IOCTL_SIOCTL_METHOD_BUFFERED,    
        &InputBuffer,
        (DWORD)strlen(InputBuffer) + 1,
        &OutputBuffer,
        sizeof(OutputBuffer),
        &BytesReturned,
        NULL);

    if (!Result)
    {
        printf("Error in DeviceIoControl : %d", GetLastError());
        return false;
    }

    printf("Output from driver: %s", OutputBuffer);


    return true;
}

int
main()
{
    std::string CpuId;

    PrintAppearance();
    CpuId = GetCpuID();
    printf("[*] The CPU Vendor is : %s\n", CpuId.c_str());

    if (CpuId == "GenuineIntel")
    {
        printf("[*] The Processor virtualization technology is VT-x. \n");
    }
    else
    {
        printf("[*] This program is not designed to run in a non-VT-x environment !\n");
        char a = getchar();
        return 1;
    }

    if (DetectVmxSupport())
    {
        printf("[*] VMX Operation is supported by your processor: .\n");
    }
    else
    {
        printf("[*] VMX Operation is not supported by your processor .\n");
        
       

        return 1;
    }


    
        
    HANDLE drvHandle = CreateFile(L"\\\\.\\MyHypervisor",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ |
        FILE_SHARE_WRITE,
        NULL, /// lpSecurityAttirbutes
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL |
        FILE_FLAG_OVERLAPPED,
        NULL); /// lpTemplateFile


    if (drvHandle == INVALID_HANDLE_VALUE)
    {
        DWORD ErrNum = GetLastError();
        printf("[*] CreateFile failed : %d\n", ErrNum);
        return 1;
    }



  

    bool result = TestIOCTL(drvHandle);

    if (!result) {
        printf("***Couldn't test IOCTL, DeviceIOControl function failed");
    }

        
    // closing driver handle
    CloseHandle(drvHandle);

    char a = getchar();


    return 0;
}
