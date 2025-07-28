#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>
#include "MSR.h"
#include "VMX.h"
#include <intrin.h>




int
MathPower(int Base, size_t Exponent)
{
    int Result = 1;
    for (;;)
    {
        if (Exponent & 1)
        {
            Result *= Base;
        }

        Exponent >>= 1;
        if (!Exponent)
        {
            break;
        }
        Base *= Base;
    }
    return Result;
}


void
RunOnEachLogicalProcessor(void* (*FunctionPtr)()) //runs the given function in each logical processor
{
    KAFFINITY AffinityMask;
    for (size_t i = 0; i < KeQueryActiveProcessors(); i++)
    {
        AffinityMask = MathPower(2, i);
        KeSetSystemAffinityThread(AffinityMask);

        DbgPrint("=====================================================");
        DbgPrint("Current thread is executing in %zu th logical processor.", i);

        FunctionPtr();
    }
}
bool
DetectVmxSupport() {

    /*
        check whether vmx support is enabled in processor
        - using the CPUID command for info about the cpu when eax = 1 and check the 5th bit in ecx
    */

    int cpuinfo[4] = { 0 };
    __cpuid(cpuinfo, 1);

    bool vmxsupported = (cpuinfo[2] & (1 << 5)) != 0;

    return vmxsupported;

}
BOOLEAN
IsVmxSupported()
{
    CPUID Data = { 0 };

    //
    // Check for the VMX bit
    //
    if (!DetectVmxSupport())
        return FALSE;

    IA32_FEATURE_CONTROL_MSR Control = { 0 };
    Control.All = __readmsr(MSR_IA32_FEATURE_CONTROL);

    //
    // BIOS lock check
    //
    if (Control.Fields.Lock == 0)
    {
        Control.Fields.Lock = TRUE;
        Control.Fields.EnableVmxon = TRUE;
        __writemsr(MSR_IA32_FEATURE_CONTROL, Control.All);
    }
    else if (Control.Fields.EnableVmxon == FALSE)
    {
        DbgPrint("[*] VMX locked off in BIOS");
        return FALSE;
    }

    return TRUE;
}




















