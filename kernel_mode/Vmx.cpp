#include "MSR.h"
#include "VMX.h"
#include "EPT.h"
#include <intrin.h>
#include <wdm.h>


#define VMX_CHECK_SUCCESS(value, field)       \
    if ((value) != 0) {                       \
        DbgPrint("[*] VMWRITE failed for %s\n", #field); \
        return FALSE;                         \
    }






int ProcessorCounts;
extern long  g_StackPointerForReturning;
extern long g_BasePointerforReturning;
VIRTUAL_MACHINE_STATE* g_GuestState = NULL;
UINT64* g_VirtualGuestMemoryAddress = NULL;


//check if vmx is supported in processor, allocate memory for each logical processor and enable vmx operations
BOOLEAN
InitializeVmx() 
{
    if (!IsVmxSupported())
    {
        DbgPrint("[*] VMX is not supported in this machine !");
        return FALSE;
    }
    
    ProcessorCounts = KeQueryActiveProcessorCount(0);

    g_GuestState = (VIRTUAL_MACHINE_STATE*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(VIRTUAL_MACHINE_STATE) * ProcessorCounts, POOLTAG);

    if (g_GuestState == NULL){
        DbgPrint("[*] allocation of virtual machines states failed!");
        return FALSE;
    }
    

    DbgPrint("\n=====================================================\n");

    KAFFINITY AffinityMask;
    
    for (size_t i = 0; i < ProcessorCounts; i++)
    {
        AffinityMask = MathPower(2, i);
        KeSetSystemAffinityThread(AffinityMask);
        // do st here !
        DbgPrint("\t\tCurrent thread is executing in %zu th logical processor.\n", i);

        AsmEnableVmxOperation(); // Enabling VMX Operation

        DbgPrint("[*] VMX Operation Enabled Successfully !\n");

        AllocateVmxonRegion(&g_GuestState[i]);
        AllocateVmcsRegion(&g_GuestState[i]);

        DbgPrint("[*] VMCS Region is allocated at  ===============> %llx\n", g_GuestState[i].VmcsRegion);
        DbgPrint("[*] VMXON Region is allocated at ===============> %llx\n", g_GuestState[i].VmxonRegion);

        DbgPrint("\n=====================================================\n");
    }
    

    return TRUE;
}
// Initializes the specified VMCS and sets its launch state to Clear
BOOLEAN
ClearVmcsState(VIRTUAL_MACHINE_STATE* GuestState)
{
    // Clear the state of the VMCS to inactive
    int status = __vmx_vmclear(&GuestState->VmcsRegion);

    DbgPrint("[*] VMCS VMCLAEAR Status is : %d\n", status);
    if (status)
    {
        // Otherwise, terminate the VMX
        DbgPrint("[*] VMCS failed to clear with status %d\n", status);
        __vmx_off();
        return FALSE;
    }
    return TRUE;
}
// Loads the pointer to the curretn VMCS from the specified address
BOOLEAN
LoadVmcs(VIRTUAL_MACHINE_STATE* GuestState)
{
    int status = __vmx_vmptrld(&GuestState->VmcsRegion);
    if (status)
    {
        DbgPrint("[*] VMCS failed with status %d\n", status);
        return FALSE;
    }
    DbgPrint("[*] VMCS VMPTRLD Status is : %d\n", status);

    return TRUE;
}

BOOLEAN
GetSegmentDescriptor(PSEGMENT_SELECTOR SegmentSelector,
    USHORT            Selector,
    PUCHAR            GdtBase)
{
    PSEGMENT_DESCRIPTOR SegDesc;

    if (!SegmentSelector)
        return FALSE;

    if (Selector & 0x4)
    {
        return FALSE;
    }

    SegDesc = (PSEGMENT_DESCRIPTOR)((PUCHAR)GdtBase + (Selector & ~0x7));

    SegmentSelector->SEL = Selector;
    SegmentSelector->BASE = SegDesc->BASE0 | SegDesc->BASE1 << 16 | SegDesc->BASE2 << 24;
    SegmentSelector->LIMIT = SegDesc->LIMIT0 | (SegDesc->LIMIT1ATTR1 & 0xf) << 16;
    SegmentSelector->ATTRIBUTES.UCHARs = SegDesc->ATTR0 | (SegDesc->LIMIT1ATTR1 & 0xf0) << 4;

    if (!(SegDesc->ATTR0 & 0x10))
    { // LA_ACCESSED
        ULONG64 Tmp;
        // this is a TSS or callgate etc, save the base high part
        Tmp = (*(PULONG64)((PUCHAR)SegDesc + 8));
        SegmentSelector->BASE = (SegmentSelector->BASE & 0xffffffff) | (Tmp << 32);
    }

    if (SegmentSelector->ATTRIBUTES.Fields.G)
    {
        // 4096-bit granularity is enabled for this segment, scale the limit
        SegmentSelector->LIMIT = (SegmentSelector->LIMIT << 12) + 0xfff;
    }

    return TRUE;
}

VOID
FillGuestSelectorData(
    PVOID  GdtBase,
    ULONG  FieldBase, // Expecting GUEST_ES_SELECTOR, GUEST_CS_SELECTOR, etc.
    USHORT Selector)
{
    SEGMENT_SELECTOR SegmentSelector = { 0 };
    ULONG AccessRights = 0;

    GetSegmentDescriptor(&SegmentSelector, Selector, (PUCHAR)GdtBase);

    // Build AccessRights properly
    AccessRights = *(ULONG*)&SegmentSelector.ATTRIBUTES;  // only if your struct matches!

    if (!Selector) {
        AccessRights |= (1 << 16);  // Unusable bit
        SegmentSelector.BASE = 0;
        SegmentSelector.LIMIT = 0;
    }

    __vmx_vmwrite(FieldBase + 0, Selector);
    __vmx_vmwrite(FieldBase + 2, SegmentSelector.LIMIT);
    __vmx_vmwrite(FieldBase + 4, AccessRights);
    __vmx_vmwrite(FieldBase + 8, SegmentSelector.BASE);
}

ULONG AdjustControls(ULONG Ctl, ULONG Msr)
{
    MSR MsrValue = { 0 };

    // Attempt to read the MSR
    __try {
        MsrValue.Content = __readmsr(Msr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Handle MSR read failure
        DbgPrint("Failed to read MSR: 0x%X\n", Msr);
        return 0; // Return an invalid control value or a default
    }

    // Adjust controls based on MSR's "allowed-0" and "allowed-1" bits
    Ctl &= MsrValue.MSR_EDGES.High; /* Bit == 0 in High Word => Must be Zero */
    Ctl |= MsrValue.MSR_EDGES.Low;  /* Bit == 1 in Low Word  => Must be One */

    return Ctl;
}



VOID
MainVmexitHandler(PGUEST_REGS GuestRegs)
{

    UNREFERENCED_PARAMETER(GuestRegs);


    ULONG ExitReason = 0;
    __vmx_vmread(VM_EXIT_REASON, (size_t*)&ExitReason);

    ULONG ExitQualification = 0;
    __vmx_vmread(EXIT_QUALIFICATION, (size_t*)&ExitQualification);

    DbgPrint("\nVM_EXIT_REASION 0x%x\n", ExitReason & 0xffff);
    DbgPrint("EXIT_QUALIFICATION 0x%x\n", ExitQualification);

    switch (ExitReason)
    {
      
    case EXIT_REASON_HLT:
    {
        AsmVmxoffAndRestoreState();

        break;
    }

  
    case EXIT_REASON_VMCALL:
    {
        AsmVmxoffAndRestoreState();
        DbgPrint("executing of vmcall detected");


        break;
    }
    case EXIT_REASON_EPT_VIOLATION:
    {

        AsmVmxoffAndRestoreState();

        DbgPrint("Ept violation detected");
        break;
    }

    default:
    {
              
        AsmVmxoffAndRestoreState();

        break;
    }
    }
}

BOOLEAN ExecuteFunction() {

    long long result;
    ULONG64 guestFunc;
    __vmx_vmread(GUEST_RIP, &guestFunc);

    
    if (guestFunc == (ULONG64)AsmReadTimeStamp) {

         result = AsmReadTimeStamp();
        DbgPrint("result of Read Time Stamp: %lld", result);
        return TRUE;

    }
    if (guestFunc == (ULONG64)AsmAdd) {

         result = AsmAdd();
        DbgPrint("result of Add: %lld", result);
        return TRUE;

    }
    if (guestFunc == (ULONG64)AsmXor) {

         result = AsmXor();
        DbgPrint("result of Xor: %lld", result);
        return TRUE;

    }
    if (guestFunc == (ULONG64)AsmNop) {

         AsmNop();
       
        return TRUE;

    }

    return FALSE;

}

BOOLEAN
SetupVmcs(VIRTUAL_MACHINE_STATE* GuestState, PEPTP EPTP, ULONG64 function) {


    BOOLEAN Status = FALSE;

    // Load Extended Page Table Pointer
    VMX_CHECK_SUCCESS(__vmx_vmwrite(EPT_POINTER, EPTP->All), EPT_POINTER);

    ULONG64          GdtBase = 0;
    SEGMENT_SELECTOR SegmentSelector = { 0 };


    VMX_CHECK_SUCCESS(__vmx_vmwrite(HOST_ES_SELECTOR, GetEs() & 0xF8), HOST_ES_SELECTOR);
    VMX_CHECK_SUCCESS(__vmx_vmwrite(HOST_CS_SELECTOR, GetCs() & 0xF8), HOST_CS_SELECTOR);
    VMX_CHECK_SUCCESS(__vmx_vmwrite(HOST_SS_SELECTOR, GetSs() & 0xF8), HOST_SS_SELECTOR);
    VMX_CHECK_SUCCESS(__vmx_vmwrite(HOST_DS_SELECTOR, GetDs() & 0xF8), HOST_DS_SELECTOR);
    VMX_CHECK_SUCCESS(__vmx_vmwrite(HOST_FS_SELECTOR, GetFs() & 0xF8), HOST_FS_SELECTOR);
    VMX_CHECK_SUCCESS(__vmx_vmwrite(HOST_GS_SELECTOR, GetGs() & 0xF8), HOST_GS_SELECTOR);
    VMX_CHECK_SUCCESS(__vmx_vmwrite(HOST_TR_SELECTOR, GetTr() & 0xF8), HOST_TR_SELECTOR);



    // VMCS Link Pointer
    VMX_CHECK_SUCCESS(__vmx_vmwrite(VMCS_LINK_POINTER, ~0ULL), VMCS_LINK_POINTER);

    // Guest Debug Controls
    VMX_CHECK_SUCCESS(__vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(MSR_IA32_DEBUGCTL) & 0xFFFFFFFF), GUEST_IA32_DEBUGCTL);
    VMX_CHECK_SUCCESS(__vmx_vmwrite(GUEST_IA32_DEBUGCTL_HIGH, __readmsr(MSR_IA32_DEBUGCTL) >> 32), GUEST_IA32_DEBUGCTL_HIGH);

    // Timestamp Counter Offset
    VMX_CHECK_SUCCESS(__vmx_vmwrite(TSC_OFFSET, 0), TSC_OFFSET);
    VMX_CHECK_SUCCESS(__vmx_vmwrite(TSC_OFFSET_HIGH, 0), TSC_OFFSET_HIGH);

    // Other VMCS Fields
    VMX_CHECK_SUCCESS(__vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0), PAGE_FAULT_ERROR_CODE_MASK);
    VMX_CHECK_SUCCESS(__vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0), PAGE_FAULT_ERROR_CODE_MATCH);


    VMX_CHECK_SUCCESS(__vmx_vmwrite(VM_EXIT_MSR_STORE_COUNT, 0), VM_EXIT_MSR_STORE_COUNT);
    VMX_CHECK_SUCCESS(__vmx_vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0), VM_EXIT_MSR_LOAD_COUNT);
    VMX_CHECK_SUCCESS(__vmx_vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0), VM_ENTRY_MSR_LOAD_COUNT);
    VMX_CHECK_SUCCESS(__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0), VM_ENTRY_INTR_INFO_FIELD);

    // Load Guest State
    GdtBase = GetGdtBase();
    FillGuestSelectorData((PVOID)GdtBase, ES, GetEs());
    FillGuestSelectorData((PVOID)GdtBase, CS, GetCs());
    FillGuestSelectorData((PVOID)GdtBase, SS, GetSs());
    FillGuestSelectorData((PVOID)GdtBase, DS, GetDs());
    FillGuestSelectorData((PVOID)GdtBase, FS, GetFs());
    FillGuestSelectorData((PVOID)GdtBase, GS, GetGs());
    FillGuestSelectorData((PVOID)GdtBase, LDTR, GetLdtr());
    FillGuestSelectorData((PVOID)GdtBase, TR, GetTr());

    VMX_CHECK_SUCCESS(__vmx_vmwrite(GUEST_FS_BASE, __readmsr(MSR_FS_BASE)), GUEST_FS_BASE);
    VMX_CHECK_SUCCESS(__vmx_vmwrite(GUEST_GS_BASE, __readmsr(MSR_GS_BASE)), GUEST_GS_BASE);

    VMX_CHECK_SUCCESS(__vmx_vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0), GUEST_INTERRUPTIBILITY_INFO);
    VMX_CHECK_SUCCESS(__vmx_vmwrite(GUEST_ACTIVITY_STATE, 0), GUEST_ACTIVITY_STATE); // Active state

    // Set CPU Execution Controls
    VMX_CHECK_SUCCESS(__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_HLT_EXITING | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS, MSR_IA32_VMX_PROCBASED_CTLS)), CPU_BASED_VM_EXEC_CONTROL);
    VMX_CHECK_SUCCESS(__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_CTL2_RDTSCP  | CPU_BASED_CTL2_ENABLE_EPT, MSR_IA32_VMX_PROCBASED_CTLS2)), SECONDARY_VM_EXEC_CONTROL);

    // Pin-Based ControlsS
    VMX_CHECK_SUCCESS(__vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, AdjustControls(0, MSR_IA32_VMX_PINBASED_CTLS)), PIN_BASED_VM_EXEC_CONTROL);

    // VM-Exit and VM-Entry Controls
    VMX_CHECK_SUCCESS(__vmx_vmwrite(VM_EXIT_CONTROLS, AdjustControls(VM_EXIT_IA32E_MODE | VM_EXIT_ACK_INTR_ON_EXIT, MSR_IA32_VMX_EXIT_CTLS)), VM_EXIT_CONTROLS);
    VMX_CHECK_SUCCESS(__vmx_vmwrite(VM_ENTRY_CONTROLS, AdjustControls(VM_ENTRY_IA32E_MODE, MSR_IA32_VMX_ENTRY_CTLS)), VM_ENTRY_CONTROLS);


    VMX_CHECK_SUCCESS(__vmx_vmwrite(CR3_TARGET_COUNT, 0), CR3_TARGET_COUNT);
    VMX_CHECK_SUCCESS(__vmx_vmwrite(CR3_TARGET_VALUE0, 0), CR3_TARGET_VALUE0);
    VMX_CHECK_SUCCESS(__vmx_vmwrite(CR3_TARGET_VALUE1, 0), CR3_TARGET_VALUE1);
    VMX_CHECK_SUCCESS(__vmx_vmwrite(CR3_TARGET_VALUE2, 0), CR3_TARGET_VALUE2);
    VMX_CHECK_SUCCESS(__vmx_vmwrite(CR3_TARGET_VALUE3, 0), CR3_TARGET_VALUE3);

    VMX_CHECK_SUCCESS(__vmx_vmwrite(GUEST_CR0, __readcr0()), GUEST_CR0);
    VMX_CHECK_SUCCESS(__vmx_vmwrite(GUEST_CR3, __readcr3()), GUEST_CR3);
    VMX_CHECK_SUCCESS(__vmx_vmwrite(GUEST_CR4, __readcr4()), GUEST_CR4);

    VMX_CHECK_SUCCESS(__vmx_vmwrite(GUEST_DR7, 0x400), GUEST_DR7);

    VMX_CHECK_SUCCESS(__vmx_vmwrite(HOST_CR0, __readcr0()), HOST_CR0);
    VMX_CHECK_SUCCESS(__vmx_vmwrite(HOST_CR3, __readcr3()), HOST_CR3);
    VMX_CHECK_SUCCESS(__vmx_vmwrite(HOST_CR4, __readcr4()), HOST_CR4);

    VMX_CHECK_SUCCESS(__vmx_vmwrite(GUEST_GDTR_BASE, GetGdtBase()), GUEST_GDTR_BASE);
    VMX_CHECK_SUCCESS(__vmx_vmwrite(GUEST_IDTR_BASE, GetIdtBase()), GUEST_IDTR_BASE);
    VMX_CHECK_SUCCESS(__vmx_vmwrite(GUEST_GDTR_LIMIT, GetGdtLimit()), GUEST_GDTR_LIMIT);
    VMX_CHECK_SUCCESS(__vmx_vmwrite(GUEST_IDTR_LIMIT, GetIdtLimit()), GUEST_IDTR_LIMIT);

    VMX_CHECK_SUCCESS(__vmx_vmwrite(GUEST_RFLAGS, GetRflags()), GUEST_RFLAGS);

    VMX_CHECK_SUCCESS(__vmx_vmwrite(GUEST_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS)), GUEST_SYSENTER_CS);
    VMX_CHECK_SUCCESS(__vmx_vmwrite(GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP)), GUEST_SYSENTER_EIP);
    VMX_CHECK_SUCCESS(__vmx_vmwrite(GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP)), GUEST_SYSENTER_ESP);

    GetSegmentDescriptor(&SegmentSelector, GetTr(), (PUCHAR)GetGdtBase());
    VMX_CHECK_SUCCESS(__vmx_vmwrite(HOST_TR_BASE, SegmentSelector.BASE), HOST_TR_BASE);

    VMX_CHECK_SUCCESS(__vmx_vmwrite(HOST_FS_BASE, __readmsr(MSR_FS_BASE)), HOST_FS_BASE);
    VMX_CHECK_SUCCESS(__vmx_vmwrite(HOST_GS_BASE, __readmsr(MSR_GS_BASE)), HOST_GS_BASE);

    VMX_CHECK_SUCCESS(__vmx_vmwrite(HOST_GDTR_BASE, GetGdtBase()), HOST_GDTR_BASE);
    VMX_CHECK_SUCCESS(__vmx_vmwrite(HOST_IDTR_BASE, GetIdtBase()), HOST_IDTR_BASE);

    VMX_CHECK_SUCCESS(__vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS)), HOST_IA32_SYSENTER_CS);
    VMX_CHECK_SUCCESS(__vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP)), HOST_IA32_SYSENTER_EIP);
    VMX_CHECK_SUCCESS(__vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP)), HOST_IA32_SYSENTER_ESP);


    VMX_CHECK_SUCCESS(__vmx_vmwrite(GUEST_RSP, (ULONG64)GuestState->guestStack + VMM_STACK_SIZE - 0x10), GUEST_RSP);
    VMX_CHECK_SUCCESS(__vmx_vmwrite(GUEST_RIP, function), GUEST_RIP);

    // Load Host State
    VMX_CHECK_SUCCESS(__vmx_vmwrite(HOST_RSP, (ULONG64)GuestState->vmmStack + VMM_STACK_SIZE - 0x10), HOST_RSP);
    VMX_CHECK_SUCCESS(__vmx_vmwrite(HOST_RIP, (ULONG64)asmVmexitHandler), HOST_RIP);

    // Final Status
    Status = TRUE;
    return Status;
}

BOOLEAN
LaunchVm(int ProcessorID, PEPTP EPTP, ULONG64 function)
{
    DbgPrint("\n======================== Launching VM =============================\n");
    KAFFINITY AffinityMask;
    AffinityMask = MathPower(2, ProcessorID);
    KeSetSystemAffinityThread(AffinityMask);

    DbgPrint("[*]\t\tCurrent thread is executing in %d th logical processor.\n", ProcessorID);
    

    //
    // Allocate stack for the guest
    //

    UINT64 GUEST_STACK = (UINT64)ExAllocatePool2(POOL_FLAG_NON_PAGED, VMM_STACK_SIZE, POOLTAG);
    g_GuestState[ProcessorID].guestStack = GUEST_STACK;

    if (g_GuestState[ProcessorID].guestStack == NULL)
    {
        DbgPrint("[*] Error in allocating guest Stack.\n");
        return FALSE;
    }
    RtlZeroMemory((void*)g_GuestState[ProcessorID].guestStack, VMM_STACK_SIZE);

    //
    // Allocate stack for the VM Exit Handler
    //
    UINT64 VMM_STACK_VA = (UINT64)ExAllocatePool2(POOL_FLAG_NON_PAGED, VMM_STACK_SIZE, POOLTAG);
    g_GuestState[ProcessorID].vmmStack = VMM_STACK_VA;

    if (g_GuestState[ProcessorID].vmmStack == NULL)
    {
        DbgPrint("[*] Error in allocating VMM Stack.\n");
        return FALSE;
    }
    RtlZeroMemory((void*)g_GuestState[ProcessorID].vmmStack, VMM_STACK_SIZE);


    DbgPrint("Guest RSP: 0x%llx", g_GuestState[ProcessorID].guestStack + VMM_STACK_SIZE);
    DbgPrint("Guest RIP: 0x%llx", function);
    DbgPrint("Host RSP: 0x%llx", g_GuestState[ProcessorID].vmmStack + VMM_STACK_SIZE);
    DbgPrint("Host RIP: 0x%llx", asmVmexitHandler);


    //
    // Allocate memory for MSRBitMap
    //
    g_GuestState[ProcessorID].MsrBitMap = (UINT64)MmAllocateNonCachedMemory(PAGE_SIZE); 
    if (g_GuestState[ProcessorID].MsrBitMap == NULL)
    {
        DbgPrint("[*] Error in allocating MSRBitMap.\n");
        return FALSE;
    }
    RtlZeroMemory((void*)g_GuestState[ProcessorID].MsrBitMap, PAGE_SIZE);
    g_GuestState[ProcessorID].MsrBitMapPhysical = VirtualToPhysicalAddress((void*)g_GuestState[ProcessorID].MsrBitMap);





    //
    // Clear the VMCS State
    //
    if (!ClearVmcsState(&g_GuestState[ProcessorID]))
    {
        goto ErrorReturn;
    }

    //
    // Load VMCS (Set the Current VMCS)
    //
    if (!LoadVmcs(&g_GuestState[ProcessorID]))
    {
        goto ErrorReturn;
    }
    

    DbgPrint("[*] Setting up VMCS.\n"); 
    if (!SetupVmcs(&g_GuestState[ProcessorID], EPTP, function)) 
    {

        goto ErrorReturn;

    }


    DbgPrint("[*] vmclear, vmptrld and vmcs are all ready");
    

    AsmSaveStateForVmxoff();

    if (!ExecuteFunction()) {
        goto ErrorReturn;
    }
    


    DbgPrint("[*] Executed function successfully");

    TerminateSingleThread(&g_GuestState[ProcessorID]);
    

    return TRUE;
    
    

    //
    // Return With Error
    //
ErrorReturn:

    if (g_GuestState[ProcessorID].vmmStack) {
        ExFreePool((void*)g_GuestState[ProcessorID].vmmStack);
    } 
    if (g_GuestState[ProcessorID].guestStack) {
        ExFreePool((void*)g_GuestState[ProcessorID].guestStack);
    }
    if (g_GuestState[ProcessorID].MsrBitMap) {
        MmFreeNonCachedMemory((void*)g_GuestState[ProcessorID].MsrBitMap, PAGE_SIZE);
    }


    DbgPrint("[*] Error in setting up vm or Executing\n");
    return FALSE;   
}


// free memory for each logical processor and call vmx off which deactivates VMX operation in the processor

VOID
TerminateVmx()
{
    DbgPrint("\n[*] Terminating VMX...\n");

    KAFFINITY AffinityMask;

    for (size_t i = 0; i < ProcessorCounts; i++)
    {
        AffinityMask = MathPower(2, i);
        KeSetSystemAffinityThread(AffinityMask);
        DbgPrint("\t\tCurrent thread is executing in %zu th logical processor.\n", i);

        if (g_GuestState[i].VmxonRegion != NULL && g_GuestState[i].VmcsRegion != NULL)
        {
            __vmx_off();
            MmFreeContiguousMemory(PhysicalToVirtualAddress(g_GuestState[i].VmxonRegion));
            MmFreeContiguousMemory(PhysicalToVirtualAddress(g_GuestState[i].VmcsRegion));
        }
    }

    DbgPrint("[*] VMX Operation turned off successfully. \n");
}
VOID
TerminateSingleThread(VIRTUAL_MACHINE_STATE* GuestState) {


    DbgPrint("[*] Terminating vmx and cleaning up a single thread");

    
    if (GuestState->VmxonRegion) {

        MmFreeContiguousMemory(PhysicalToVirtualAddress(GuestState->VmxonRegion));
        GuestState->VmxonRegion = NULL;

    }
    if (GuestState->VmcsRegion) {

        MmFreeContiguousMemory(PhysicalToVirtualAddress(GuestState->VmcsRegion));
        GuestState->VmcsRegion = NULL;

    }
 

    

   

}

