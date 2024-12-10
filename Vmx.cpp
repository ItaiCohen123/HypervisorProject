#include "MSR.h"
#include "VMX.h"
#include "EPT.h"
#include <intrin.h>
#include <wdm.h>






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

        DbgPrint("\t\tCurrent thread is executing in %zu th logical processor.", i);

        //
        // Enabling VMX Operation
        //
        AsmEnableVmxOperation();
        DbgPrint("[*] VMX Operation Enabled Successfully !");


        
        AllocateVmxonRegion(&g_GuestState[i]);
        AllocateVmcsRegion(&g_GuestState[i]);

        DbgPrint("[*] VMCS Region is allocated at  ===============> %llx", g_GuestState[i].VmcsRegion);
        DbgPrint("[*] VMXON Region is allocated at ===============> %llx", g_GuestState[i].VmxonRegion);
        
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
    ULONG  Segreg,
    USHORT Selector)
{
    SEGMENT_SELECTOR SegmentSelector = { 0 };
    ULONG            AccessRights;

    GetSegmentDescriptor(&SegmentSelector, Selector, (PUCHAR)GdtBase);
    AccessRights = ((PUCHAR)&SegmentSelector.ATTRIBUTES)[0] + (((PUCHAR)&SegmentSelector.ATTRIBUTES)[1] << 12);

    if (!Selector)
        AccessRights |= 0x10000;

    __vmx_vmwrite(GUEST_ES_SELECTOR + Segreg * 2, Selector);
    __vmx_vmwrite(GUEST_ES_LIMIT + Segreg * 2, SegmentSelector.LIMIT);
    __vmx_vmwrite(GUEST_ES_AR_BYTES + Segreg * 2, AccessRights);
    __vmx_vmwrite(GUEST_ES_BASE + Segreg * 2, SegmentSelector.BASE);
}
ULONG
AdjustControls(ULONG Ctl, ULONG Msr)
{
    MSR MsrValue = { 0 };

    MsrValue.Content = __readmsr(Msr);
    Ctl &= MsrValue.MSR_EDGES.High; /* bit == 0 in high word ==> must be zero */
    Ctl |= MsrValue.MSR_EDGES.Low;  /* bit == 1 in low word  ==> must be one  */
    return Ctl;
}
VOID
ResumeToNextInstruction()
{
    PVOID ResumeRIP = NULL;
    PVOID CurrentRIP = NULL;
    ULONG ExitInstructionLength = 0;

    __vmx_vmread(GUEST_RIP, (size_t*)&CurrentRIP);
    __vmx_vmread(VM_EXIT_INSTRUCTION_LEN, (size_t*)&ExitInstructionLength);

    ResumeRIP = (PCHAR)CurrentRIP + ExitInstructionLength;

    __vmx_vmwrite(GUEST_RIP, (ULONG64)ResumeRIP);
}
VOID
VmResumeInstruction()
{
    __vmx_vmresume(); // Resumes VMX non-root operation by using the current virtual machine control structure (VMCS).

    // if VMRESUME succeeds will never be here !

    ULONG64 ErrorCode = 0;
    __vmx_vmread(VM_INSTRUCTION_ERROR, &ErrorCode);
    __vmx_off();
    DbgPrint("[*] VMRESUME Error : 0x%llx\n", ErrorCode);

    //
    // It's such a bad error because we don't where to go!
    // prefer to break
    //
    DbgBreakPoint();
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
        //
        // 25.1.2  Instructions That Cause VM Exits Unconditionally
        // The following instructions cause VM exits when they are executed in VMX non-root operation: CPUID, GETSEC,
        // INVD, and XSETBV. This is also true of instructions introduced with VMX, which include: INVEPT, INVVPID,
        // VMCALL, VMCLEAR, VMLAUNCH, VMPTRLD, VMPTRST, VMRESUME, VMXOFF, and VMXON.
        //

    case EXIT_REASON_VMCLEAR:
    case EXIT_REASON_VMPTRLD:
    case EXIT_REASON_VMPTRST:
    case EXIT_REASON_VMREAD:
    case EXIT_REASON_VMRESUME:
    case EXIT_REASON_VMWRITE:
    case EXIT_REASON_VMXOFF:
    case EXIT_REASON_VMXON:
    case EXIT_REASON_VMLAUNCH:
    {
        break;
    }
    case EXIT_REASON_HLT:
    {
        DbgPrint("[*] Execution of HLT detected... \n");

        //
        // that's enough for now ;)
        //
        AsmVmxoffAndRestoreState();

        break;
    }
    case EXIT_REASON_EXCEPTION_NMI:
    {
        break;
    }

    case EXIT_REASON_CPUID:
    {
        break;
    }

    case EXIT_REASON_INVD:
    {
        break;
    }

    case EXIT_REASON_VMCALL:
    {
        break;
    }

    case EXIT_REASON_CR_ACCESS:
    {
        break;
    }

    case EXIT_REASON_MSR_READ:
    {
        break;
    }

    case EXIT_REASON_MSR_WRITE:
    {
        break;
    }

    case EXIT_REASON_EPT_VIOLATION:
    {
        break;
    }

    default:
    {
        // DbgBreakPoint();
        break;
    }
    }
}
BOOLEAN
SetupVmcs(VIRTUAL_MACHINE_STATE* GuestState, PEPTP EPTP) {

    UNREFERENCED_PARAMETER(EPTP);
    BOOLEAN Status = FALSE;

    // Load Extended Page Table Pointer
    //__vmx_vmwrite(EPT_POINTER, EPTP->All);

    ULONG64          GdtBase = 0;
    SEGMENT_SELECTOR SegmentSelector = { 0 };

    __vmx_vmwrite(HOST_ES_SELECTOR, GetEs() & 0xF8);
    __vmx_vmwrite(HOST_CS_SELECTOR, GetCs() & 0xF8);
    __vmx_vmwrite(HOST_SS_SELECTOR, GetSs() & 0xF8);
    __vmx_vmwrite(HOST_DS_SELECTOR, GetDs() & 0xF8);
    __vmx_vmwrite(HOST_FS_SELECTOR, GetFs() & 0xF8);
    __vmx_vmwrite(HOST_GS_SELECTOR, GetGs() & 0xF8);
    __vmx_vmwrite(HOST_TR_SELECTOR, GetTr() & 0xF8);


    //
   // Setting the link pointer to the required value for 4KB VMCS
   //
    __vmx_vmwrite(VMCS_LINK_POINTER, ~0ULL);

    __vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(MSR_IA32_DEBUGCTL) & 0xFFFFFFFF);
    __vmx_vmwrite(GUEST_IA32_DEBUGCTL_HIGH, __readmsr(MSR_IA32_DEBUGCTL) >> 32);

    /* Time-stamp counter offset */
    __vmx_vmwrite(TSC_OFFSET, 0);
    __vmx_vmwrite(TSC_OFFSET_HIGH, 0);

    __vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
    __vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);

    __vmx_vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);
    __vmx_vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);

    __vmx_vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
    __vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);


    GdtBase = GetGdtBase();

    FillGuestSelectorData((PVOID)GdtBase, ES, GetEs());
    FillGuestSelectorData((PVOID)GdtBase, CS, GetCs());
    FillGuestSelectorData((PVOID)GdtBase, SS, GetSs());
    FillGuestSelectorData((PVOID)GdtBase, DS, GetDs());
    FillGuestSelectorData((PVOID)GdtBase, FS, GetFs());
    FillGuestSelectorData((PVOID)GdtBase, GS, GetGs());
    FillGuestSelectorData((PVOID)GdtBase, LDTR, GetLdtr());
    FillGuestSelectorData((PVOID)GdtBase, TR, GetTr());

    __vmx_vmwrite(GUEST_FS_BASE, __readmsr(MSR_FS_BASE));
    __vmx_vmwrite(GUEST_GS_BASE, __readmsr(MSR_GS_BASE));

    __vmx_vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
    __vmx_vmwrite(GUEST_ACTIVITY_STATE, 0); // Active state

    __vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_HLT_EXITING | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS, MSR_IA32_VMX_PROCBASED_CTLS));
    __vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_CTL2_RDTSCP /* | CPU_BASED_CTL2_ENABLE_EPT*/, MSR_IA32_VMX_PROCBASED_CTLS2));


    __vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, AdjustControls(0, MSR_IA32_VMX_PINBASED_CTLS));
    __vmx_vmwrite(VM_EXIT_CONTROLS, AdjustControls(VM_EXIT_IA32E_MODE | VM_EXIT_ACK_INTR_ON_EXIT, MSR_IA32_VMX_EXIT_CTLS));
    __vmx_vmwrite(VM_ENTRY_CONTROLS, AdjustControls(VM_ENTRY_IA32E_MODE, MSR_IA32_VMX_ENTRY_CTLS));


    __vmx_vmwrite(CR3_TARGET_COUNT, 0);
    __vmx_vmwrite(CR3_TARGET_VALUE0, 0);
    __vmx_vmwrite(CR3_TARGET_VALUE1, 0);
    __vmx_vmwrite(CR3_TARGET_VALUE2, 0);
    __vmx_vmwrite(CR3_TARGET_VALUE3, 0);

    __vmx_vmwrite(GUEST_CR0, __readcr0());
    __vmx_vmwrite(GUEST_CR3, __readcr3());
    __vmx_vmwrite(GUEST_CR4, __readcr4());

    __vmx_vmwrite(GUEST_DR7, 0x400);

    __vmx_vmwrite(HOST_CR0, __readcr0());
    __vmx_vmwrite(HOST_CR3, __readcr3());
    __vmx_vmwrite(HOST_CR4, __readcr4());

    __vmx_vmwrite(GUEST_GDTR_BASE, GetGdtBase());
    __vmx_vmwrite(GUEST_IDTR_BASE, GetIdtBase());
    __vmx_vmwrite(GUEST_GDTR_LIMIT, GetGdtLimit());
    __vmx_vmwrite(GUEST_IDTR_LIMIT, GetIdtLimit());

    __vmx_vmwrite(GUEST_RFLAGS, GetRflags());

    __vmx_vmwrite(GUEST_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
    __vmx_vmwrite(GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
    __vmx_vmwrite(GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));

    GetSegmentDescriptor(&SegmentSelector, GetTr(), (PUCHAR)GetGdtBase());
    __vmx_vmwrite(HOST_TR_BASE, SegmentSelector.BASE);

    __vmx_vmwrite(HOST_FS_BASE, __readmsr(MSR_FS_BASE));
    __vmx_vmwrite(HOST_GS_BASE, __readmsr(MSR_GS_BASE));

    __vmx_vmwrite(HOST_GDTR_BASE, GetGdtBase());
    __vmx_vmwrite(HOST_IDTR_BASE, GetIdtBase());

    __vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
    __vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
    __vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));


    __vmx_vmwrite(GUEST_RSP, (ULONG64)g_VirtualGuestMemoryAddress); // setup guest sp
    __vmx_vmwrite(GUEST_RIP, (ULONG64)g_VirtualGuestMemoryAddress); // setup guest ip

    __vmx_vmwrite(HOST_RSP, ((ULONG64)GuestState->vmmStack + VMM_STACK_SIZE - 1));
    __vmx_vmwrite(HOST_RIP, (ULONG64)asmVmexitHandler);

    Status = TRUE;

    return Status;
}

BOOLEAN
LaunchVm(int ProcessorID, PEPTP EPTP)
{
    DbgPrint("\n======================== Launching VM =============================\n");
    KAFFINITY AffinityMask;
    AffinityMask = MathPower(2, ProcessorID);
    KeSetSystemAffinityThread(AffinityMask);

    DbgPrint("[*]\t\tCurrent thread is executing in %d th logical processor.\n", ProcessorID);

    PAGED_CODE();

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

    //
    // Allocate memory for MSRBitMap
    //
    g_GuestState[ProcessorID].MsrBitMap = (UINT64)MmAllocateNonCachedMemory(PAGE_SIZE); // should be aligned
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
    SetupVmcs(&g_GuestState[ProcessorID], EPTP);

   

    DbgPrint("[*] Executing VMLAUNCH.\n");

    AsmSaveStateForVmxoff();

    __vmx_vmlaunch(); // Places the calling app in VMX non-root operation state (VM enter) by using current VMCS

    //
    // if VMLAUNCH succeeds will never be here!
    //
    
    __vmx_off();      
    //DbgBreakPoint();

    DbgPrint("\n===================================================================\n");


    __vmx_off();
    DbgPrint("[*] VMXOFF Executed Successfully. !\n");

    return TRUE;



    //
    // Return With Error
    //
ErrorReturn:

    DbgPrint("[*] Fail to setup VMCS !\n");
    return FALSE;   
}
// stores the pointer to the current VMCS at the specified address
UINT64
VmptrstInstruction() 
{
    PHYSICAL_ADDRESS vmcspa;
    vmcspa.QuadPart = 0;
    __vmx_vmptrst((unsigned __int64*)&vmcspa);


    return 0;
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
        DbgPrint("\n=====================================================\n");
        DbgPrint("\t\tCurrent thread is executing in %zu th logical processor.", i);

        __vmx_off();
        MmFreeContiguousMemory(PhysicalToVirtualAddress(g_GuestState[i].VmxonRegion));
        MmFreeContiguousMemory(PhysicalToVirtualAddress(g_GuestState[i].VmcsRegion));
        
    }

    DbgPrint("[*] VMX Operation turned off successfully. \n");
}

