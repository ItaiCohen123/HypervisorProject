#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>
#include "MSR.h"
#include "VMX.h"
#include <intrin.h>




UINT64
VirtualToPhysicalAddress(void* virtualAddress)
{
    return MmGetPhysicalAddress(virtualAddress).QuadPart;
}

PVOID
PhysicalToVirtualAddress(UINT64 physicalAddress)
{
    PHYSICAL_ADDRESS PhysicalAddr;
    PhysicalAddr.QuadPart = physicalAddress; 

    return MmGetVirtualForPhysical(PhysicalAddr);
}
BOOLEAN
AllocateVmxonRegion(IN VIRTUAL_MACHINE_STATE* GuestState)
{
    // at IRQL > DISPATCH_LEVEL memory allocation routines don't work
    if (KeGetCurrentIrql() > DISPATCH_LEVEL)
        KeRaiseIrqlToDpcLevel();

    PHYSICAL_ADDRESS PhysicalMax = { 0 };
    PhysicalMax.QuadPart = MAXULONG64;

    int    VMXONSize = 2 * VMXON_SIZE;
    BYTE* Buffer = (BYTE*)MmAllocateContiguousMemory(VMXONSize + ALIGNMENT_PAGE_SIZE, PhysicalMax); // Allocating a 4-KByte Contigous Memory region

    PHYSICAL_ADDRESS Highest = { 0 }, Lowest = { 0 };
    Highest.QuadPart = ~0;


    if (Buffer == NULL)
    {
        DbgPrint("[*] Error : Couldn't Allocate Buffer for VMXON Region.");
        return FALSE; // NtStatus = STATUS_INSUFFICIENT_RESOURCES;
    }
    UINT64 PhysicalBuffer = VirtualToPhysicalAddress(Buffer);

    // zero-out memory
    RtlSecureZeroMemory(Buffer, VMXONSize + ALIGNMENT_PAGE_SIZE);
    UINT64 AlignedPhysicalBuffer = (UINT64)((ULONG_PTR)(PhysicalBuffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));

    UINT64 AlignedVirtualBuffer = (UINT64)((ULONG_PTR)(Buffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));


    // get IA32_VMX_BASIC_MSR RevisionId

    IA32_VMX_BASIC_MSR basic = { 0 };

    basic.All = __readmsr(MSR_IA32_VMX_BASIC);


    // Changing Revision Identifier
    *(UINT64*)AlignedVirtualBuffer = basic.Fields.RevisionIdentifier;

    int Status = __vmx_on(&AlignedPhysicalBuffer);
    if (Status)
    {
        DbgPrint("[*] VMXON failed with status %d\n", Status);
        return FALSE;
    }

    GuestState->VmxonRegion = AlignedPhysicalBuffer;

    return TRUE;
}
BOOLEAN
AllocateVmcsRegion(IN VIRTUAL_MACHINE_STATE* GuestState)
{
    //
    // at IRQL > DISPATCH_LEVEL memory allocation routines don't work
    //
    if (KeGetCurrentIrql() > DISPATCH_LEVEL)
        KeRaiseIrqlToDpcLevel();

    PHYSICAL_ADDRESS PhysicalMax = { 0 };
    PhysicalMax.QuadPart = MAXULONG64;

    int    VMCSSize = 2 * VMCS_SIZE;
    BYTE* Buffer = (BYTE*)MmAllocateContiguousMemory(VMCSSize + ALIGNMENT_PAGE_SIZE, PhysicalMax); // Allocating a 4-KByte Contigous Memory region

    PHYSICAL_ADDRESS Highest = { 0 }, Lowest = { 0 };
    Highest.QuadPart = ~0;


    UINT64 PhysicalBuffer = VirtualToPhysicalAddress(Buffer);
    if (Buffer == NULL)
    {
        DbgPrint("[*] Error : Couldn't Allocate Buffer for VMCS Region.");
        return FALSE; // ntStatus = STATUS_INSUFFICIENT_RESOURCES;
    }
    // zero-out memory
    RtlSecureZeroMemory(Buffer, VMCSSize + ALIGNMENT_PAGE_SIZE);
    UINT64 AlignedPhysicalBuffer = (UINT64)((ULONG_PTR)(PhysicalBuffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));

    UINT64 AlignedVirtualBuffer = (UINT64)((ULONG_PTR)(Buffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));


    // get IA32_VMX_BASIC_MSR RevisionId

    IA32_VMX_BASIC_MSR basic = { 0 };

    basic.All = __readmsr(MSR_IA32_VMX_BASIC);


    // Changing Revision Identifier
    *(UINT64*)AlignedVirtualBuffer = basic.Fields.RevisionIdentifier;

    int Status = __vmx_vmptrld(&AlignedPhysicalBuffer);
    if (Status)
    {
        DbgPrint("[*] VMCS failed with status %d\n", Status);
        return FALSE;
    }

    GuestState->VmcsRegion = AlignedPhysicalBuffer;

    return TRUE;
}

























