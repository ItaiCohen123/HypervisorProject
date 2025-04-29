#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>
#include <intrin.h>
#include "VMX.h"
#include "EPT.h"



#define IOCTL_Device_Function CTL_CODE(DeviceType, Function, Method, Access)

//defining all the IOCTL control codes:

#define IOCTL_SIOCTL_METHOD_BUFFERED CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SIOCTL_METHOD_NEITHER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_SIOCTL_METHOD_IN_DIRECT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_IN_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_SIOCTL_METHOD_OUT_DIRECT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

int proccessId = -1;
PEPTP eptp;





VOID
StartVM(PVOID function) {

    DbgPrint("[*] inside StartVM ");
    

    proccessId++;

    if (proccessId <= 11) {

        bool result;
        result = LaunchVm(proccessId, eptp, (ULONG64)function);

        if (!result)
            DbgPrint("[*] An error accured");

    }
    else {
        DbgPrint("[*] Reached the maximum amount of cpu cores available therefore can't start another vm");
    }

    PsTerminateSystemThread(STATUS_SUCCESS); // ending thread

    


}


NTSTATUS
DrvUnsupported(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    DbgPrint("[*] This function is not supported :( !");
    DbgPrint("[*] DrvUnsupported called");


    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}


NTSTATUS
DrvCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    /*
        
        this function is called when the user mode application starts
        
    */

    DbgPrint("[*] Driver Create called");

   
    
  
    UNREFERENCED_PARAMETER(DeviceObject);


    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS
DrvIoctlDispatcher(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{

    /*
    
        this function purpose is to communicate with the user mode
    
    */


    DbgPrint("[*] DrvIoctlDispatcher called");

    PIO_STACK_LOCATION IrpStack;                  // Pointer to current stack location
    NTSTATUS           NtStatus = STATUS_SUCCESS; // Assume success
    ULONG              InBufLength;               // Input buffer length
    ULONG              OutBufLength;              // Output buffer length
    PCHAR              InBuf, OutBuf;             // pointer to Input and output buffer

    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    IrpStack = IoGetCurrentIrpStackLocation(Irp);
    InBufLength = IrpStack->Parameters.DeviceIoControl.InputBufferLength;
    OutBufLength = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;


    if (!InBufLength || !OutBufLength)
    {
        NtStatus = STATUS_INVALID_PARAMETER;
        goto End;
    }

 
  
    switch (IrpStack->Parameters.DeviceIoControl.IoControlCode)
    {
        case IOCTL_SIOCTL_METHOD_BUFFERED: // method buffered
            /*
            
                This method is typically used for transferring small amounts of data per request.
                Most I/O control codes for device and intermediate drivers use this type
                as Windows copies the user-mode buffer to the kernel-mode
                and the kernel-mode buffer to the user-mode.

            */
            DbgPrint("[*] Method Buffered used");

            InBuf = (char*)Irp->AssociatedIrp.SystemBuffer;
            OutBuf = (char*)Irp->AssociatedIrp.SystemBuffer;
            DbgPrint("--Input from user: %s", InBuf);

            if (strcmp(InBuf, "NOP") == 0) {

                DbgPrint("[*] Executing %s in guest", InBuf);
                HANDLE threadHandle;

                NTSTATUS result = PsCreateSystemThread(
                    &threadHandle,
                    THREAD_ALL_ACCESS,
                    NULL,
                    NULL,
                    NULL,
                    StartVM,
                    AsmNop
                );

                if (result != STATUS_SUCCESS) {

                    DbgPrint("Create thread failed!!!");

                }
                break;
            }
            if (strcmp(InBuf, "RDTS") == 0) {



                DbgPrint("[*] Executing %s in guest", InBuf);

                HANDLE threadHandle;

                NTSTATUS result = PsCreateSystemThread(
                &threadHandle,
                THREAD_ALL_ACCESS,
                NULL,
                NULL,
                NULL,
                StartVM,
                AsmReadTimeStamp
                );

                if (result != STATUS_SUCCESS) {

                    DbgPrint("Create thread failed!!!");
                    break;
                }

                DbgPrint("[*] Created Thread Successfully");

                break;
               
            }
            if (strcmp(InBuf, "ADD") == 0) {



                DbgPrint("[*] Executing %s in guest", InBuf);

                HANDLE threadHandle;

                NTSTATUS result = PsCreateSystemThread(
                    &threadHandle,
                    THREAD_ALL_ACCESS,
                    NULL,
                    NULL,
                    NULL,
                    StartVM,
                    AsmAdd
                );

                if (result != STATUS_SUCCESS) {

                    DbgPrint("Create thread failed!!!");
                    break;
                }

                DbgPrint("[*] Created Thread Successfully");

                break;

            }
            if (strcmp(InBuf, "XOR") == 0) {

                DbgPrint("[*] Executing %s in guest", InBuf);

                HANDLE threadHandle;

                NTSTATUS result = PsCreateSystemThread(
                    &threadHandle,
                    THREAD_ALL_ACCESS,
                    NULL,
                    NULL,
                    NULL,
                    StartVM,
                    AsmXor
                );

                if (result != STATUS_SUCCESS) {

                    DbgPrint("Create thread failed!!!");
                    break;
                }

                DbgPrint("[*] Created Thread Successfully");

                break;

            }
           


            /* 
                This is a very convinient way of recieving input from user.
                In the future when I will have GUI when the user clicks a button I can transfer information
                to the driver using this function.
                For example: start vm, stop vm, take snapshot...

            */
          



            Irp->IoStatus.Information = (OutBufLength);


            break;


        default:

            //
            // The specified I/O control code is unrecognized by this driver.
            //
            NtStatus = STATUS_INVALID_DEVICE_REQUEST;
            DbgPrint("This method is not supported");
            break;
    }



    End:

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}


NTSTATUS
DrvClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    DbgPrint("[*] DrvClose called");

    



    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

VOID
DrvUnload(PDRIVER_OBJECT DriverObject)
{

    

    UNICODE_STRING DosDeviceName;

    DbgPrint("DrvUnload Called !");
    TerminateVmx();


    RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\MyHypervisor");

    IoDeleteSymbolicLink(&DosDeviceName);
    IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{

   

    /*
    
        this function is called when the driver is first loaded
        - sets up all major function, device object, symbolic link, vmx support detection
        
    */



    UNREFERENCED_PARAMETER(RegistryPath);

    

    NTSTATUS       NtStatus = STATUS_SUCCESS;
    PDEVICE_OBJECT DeviceObject = NULL;
    UINT64 Index = 0;
    UNICODE_STRING DriverName, DosDeviceName;
    
    DbgPrint("[*] DriverEntry Called.");

  
    // setting up names
    RtlInitUnicodeString(&DriverName, L"\\Device\\MyHypervisor");
    RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\MyHypervisor");

    // create device
    NtStatus = IoCreateDevice(
        DriverObject,
        0,
        &DriverName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &DeviceObject
        );

    if (NtStatus == STATUS_SUCCESS)
    {
        for (Index = 0; Index < IRP_MJ_MAXIMUM_FUNCTION; Index++)
        {
            DriverObject->MajorFunction[Index] = DrvUnsupported;
        }

        DbgPrint("[*] Setting Devices major functions.");
        DriverObject->MajorFunction[IRP_MJ_CLOSE] = DrvClose;
        DriverObject->MajorFunction[IRP_MJ_CREATE] = DrvCreate;
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DrvIoctlDispatcher;

       

        DriverObject->DriverUnload = DrvUnload;

        IoCreateSymbolicLink(&DosDeviceName, &DriverName);
    }
    else
    {
        DbgPrint("[*] There were some errors in creating device.");
    }

    
        // Initiating EPTP
        
    eptp = InitializeEptp();

    if (!InitializeVmx())
    {
        DbgPrint("[*] couldn't initialize vmx");
        return FALSE;

    }

    DbgPrint("[*] VMX Initiated Successfully.");
    DbgPrint("[*] VMXON called");

    
    
   
    return NtStatus;
}


