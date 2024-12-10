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





extern "C" long long AsmEnableVmxOperation(void);

VOID
PrintIrpInfo(PIRP Irp)
{
    /*
        this function prints information about the Irp, input buffers, sizes
    */

    PIO_STACK_LOCATION  IrpStack;
    IrpStack = IoGetCurrentIrpStackLocation(Irp);

    PAGED_CODE();

    // print the input buffer
    DbgPrint("\tIrp->AssociatedIrp.SystemBuffer = 0x%p\n", Irp->AssociatedIrp.SystemBuffer);

    // output buffer
    DbgPrint("\tIrp->UserBuffer = 0x%p\n", Irp->UserBuffer);

    // print input buffer in method neither
    DbgPrint("\tIrpStack->Parameters.DeviceIoControl.Type3InputBuffer = 0x%p\n", IrpStack->Parameters.DeviceIoControl.Type3InputBuffer);

    // print input buffer size
    DbgPrint("\tIrpStack->Parameters.DeviceIoControl.InputBufferLength = %d\n", IrpStack->Parameters.DeviceIoControl.InputBufferLength);

    // print output buffer size
    DbgPrint("\tIrpStack->Parameters.DeviceIoControl.OutputBufferLength = %d\n", IrpStack->Parameters.DeviceIoControl.OutputBufferLength);


    return;
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
DrvRead(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    DbgPrint("[*] DrvRead called");

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS
DrvCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    /*
        
        this function is called when the user mode application starts it
        
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
    char str[] = "This String is from Device Driver !!!";

    PIO_STACK_LOCATION IrpStack;                  // Pointer to current stack location
    NTSTATUS           NtStatus = STATUS_SUCCESS; // Assume success
    ULONG              InBufLength;               // Input buffer length
    ULONG              OutBufLength;              // Output buffer length
    PCHAR              InBuf, OutBuf;             // pointer to Input and output buffer
    PCHAR              Data = str;
    size_t             DataLen = strlen(Data) + 1; // Length of data including null
    //PCHAR              Buffer = NULL;

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

    //
   // Determine which I/O control code was specified. (buffered/neither/in_direct/out_direct
   //

  
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
           // PrintIrpInfo(Irp);

            InBuf = (char*)Irp->AssociatedIrp.SystemBuffer;
            OutBuf = (char*)Irp->AssociatedIrp.SystemBuffer;
            DbgPrint("--Input from user: %s", InBuf);

            RtlCopyBytes(OutBuf, Data, OutBufLength);   


            Irp->IoStatus.Information = (OutBufLength < DataLen ? OutBufLength : DataLen);


            break;

        case IOCTL_SIOCTL_METHOD_NEITHER: // method neither
            /*
                
                This method is neither buffered nor direct I/O.
                The I/O manager does not provide any system buffers,
                and the IRP provides the user-mode virtual addresses of the input and output buffers
                without validating or mapping them.
            
            */
        
            DbgPrint("[*] Method Neither used");
            PrintIrpInfo(Irp);



            break;

        case IOCTL_SIOCTL_METHOD_IN_DIRECT: // method in direct
            /*
                
                This type is generally used for reading or writing large amounts of data 
                that must be transferred fast as it won’t copy the data and instead shares the pages.
            
            */
        
            DbgPrint("[*] Method In Direct used");
            PrintIrpInfo(Irp);


            break;

        case IOCTL_SIOCTL_METHOD_OUT_DIRECT: // method out direct
            /*
                
                This type is generally used for reading or writing large amounts of data 
                that must be transferred fast as it won’t copy the data and instead shares the pages.
            
            */
        
            DbgPrint("[*] Method Out Direct used");
            PrintIrpInfo(Irp);


            break;

        default:

            //
            // The specified I/O control code is unrecognized by this driver.
            //
            NtStatus = STATUS_INVALID_DEVICE_REQUEST;
            DbgPrint("ERROR: unrecognized IOCTL %x\n",
                IrpStack->Parameters.DeviceIoControl.IoControlCode);
            break;
    }



    End:

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}


NTSTATUS
DrvWrite(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    DbgPrint("[*] DrvWrite called");

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

    //
  // executing VMXOFF on every logical processor
  //
    TerminateVmx();
    DbgPrint("[*] VMXOFF called");


    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

VOID
DrvUnload(PDRIVER_OBJECT DriverObject)
{

    /*
    
        called when the driver is ending (by um request)
    
    */

    UNICODE_STRING DosDeviceName;

    DbgPrint("DrvUnload Called !");

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

        DriverObject->MajorFunction[IRP_MJ_READ] = DrvRead;
        DriverObject->MajorFunction[IRP_MJ_WRITE] = DrvWrite;

        DriverObject->DriverUnload = DrvUnload;

        IoCreateSymbolicLink(&DosDeviceName, &DriverName);
    }
    else
    {
        DbgPrint("[*] There were some errors in creating device.");
    }

   
  
    __try
    {
        //
        // Initiating EPTP and VMX
        //
        PEPTP EPTP = InitializeEptp();
        UNREFERENCED_PARAMETER(EPTP);

        if (!InitializeVmx())
        {
            DbgPrint("[*] couldn't initialize vmx");

        }

        DbgPrint("[*] VMX Initiated Successfully.");
        DbgPrint("[*] VMXON called");


        
        UINT8 hltInstruction = 0xF4;
        size_t numberOfCopies = (100 * PAGE_SIZE) - 1; // Number of times the HLT instruction will be copied
        SIZE_T allocateSize = sizeof(UINT8) * numberOfCopies + 1;

        DbgPrint("[*] Allocating %llu bytes of non-paged memory\n", allocateSize);

        g_VirtualGuestMemoryAddress = (UINT64*)ExAllocatePool2(POOL_FLAG_NON_PAGED, allocateSize, 'tag1');
        if (g_VirtualGuestMemoryAddress == NULL) {
            DbgPrint("[*] Failed to allocate virtual guest memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        DbgPrint("[*] Memory allocated successfully at %p\n", g_VirtualGuestMemoryAddress);
      

        RtlFillMemory(g_VirtualGuestMemoryAddress, allocateSize, hltInstruction); // Fill memory



        DbgPrint("[*] Memory filled successfully\n");
       

        //
        // Launching VM for Test (in the 0th virtual processor)
        //



        int ProcessorID = 0;

        LaunchVm(ProcessorID, EPTP);
        
        
    }
    __except (GetExceptionCode())
    {
        DbgPrint("[*] Couldn't initialize ept and launch vm");
    }

    return NtStatus;
}


