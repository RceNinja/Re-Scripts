__author__  = "Behrooz Abbassi @rceninja"
__license__ = "MIT"
__version__ = "2.0.0"


"""
You can use this script to find and decode all (I hope!) MSRs and VMCSs in hypervisor binaries,
it also has a siple gui that enables you to search in founded values by Adddress, Name and Const values
In addition to searching and decoding, you can set proper comments or symbolic constant on these values
automatically
"""


import collections
import os

# IDAPython 
import idaapi
import idautils
import idc
import struct
# ------------------------------------------------------------------------------------- #
"""
If you enable this mode, the script will try to find and decode more MSRs and VMCS by appling more
analysis on the binary, BUT because of linear analysis there is some false positives, which can cause 
some problems :-( so this mode is disabled by default


Examples

mov     rbx, 681Ch ; VMCS_GUEST_RSP
vmwrite rbx, rsi

This is the basic form of calling vmwrite this one is easy to figure but what about next examples?

mov     rax, 681Ch ; VMCS_GUEST_RSP
mov     rbx, rax 
vmwrite rbx, rsi


mov     eax, 681Ch ; VMCS_GUEST_RSP
call    Function_0()
mov     ecx, eax 
vmwrite ecx, rsi

"""
cfg_enable_smart_mode        = False
cfg_smart_mode_max_back_step = 10

# ------------------------------------------------------------------------------------- #
g_knowledge_db = None
# ------------------------------------------------------------------------------------- #
def AddSymbolicConstantsEnumsToIda():
    # ------------------------------------------------------------------------------------- #
    # Based on @AmarSaar post [https://msrc-blog.microsoft.com/2018/12/10/first-steps-in-hyper-v-research]
    # Notice these values can change between different builds!
    # ------------------------------------------------------------------------------------- #
    id = idc.AddEnum(0, "HYPERV_STRUCTS", idaapi.hexflag())
    idc.AddConstEx(id, "Self", 0, -1)
    idc.AddConstEx(id, "CpuIndex", 8, -1)
    idc.AddConstEx(id, "CurrentThread", 0x38, -1)
    idc.AddConstEx(id, "LogicalCpuIndex", 0x8080, -1)
    idc.AddConstEx(id, "CurrentVP", 0x82E0, -1)
    idc.AddConstEx(id, "IDT", 0x8340, -1)
    idc.AddConstEx(id, "GDT", 0x8348, -1)
    idc.AddConstEx(id, "CurrentPartition", 0x83A8, -1)
    idc.AddConstEx(id, "CurrentVMCS", 0x186E0, -1)



    #https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/hvilib/hviintel/cpuid_result.htm
    id = idc.AddEnum(0, "HV_CPUID_FUNCTION_ENUM", idaapi.hexflag())
    idc.AddConstEx(id, "HvCpuIdFunctionVersionAndFeatures", 0x00000001, -1)
    idc.AddConstEx(id, "HvCpuIdFunctionHvVendorAndMaxFunction", 0x40000000, -1)
    idc.AddConstEx(id, "HvCpuIdFunctionHvInterface", 0x40000001, -1)
    idc.AddConstEx(id, "HvCpuIdFunctionMsHvVersion", 0x40000002, -1)
    idc.AddConstEx(id, "HvCpuIdFunctionMsHvFeatures", 0x40000003, -1)
    idc.AddConstEx(id, "HvCpuIdFunctionMsHvEnlightenmentInformation",0x40000004, -1)
    idc.AddConstEx(id, "HvCpuIdFunctionMsHvImplementationLimits", 0x40000005, -1)

    idc.AddConstEx(id, "HvCpuIdFunctionMsHvHardwareFeatures", 0x40000006, -1)
    idc.AddConstEx(id, "HvCpuIdFunctionMsHvCpuManagementFeatures", 0x40000007, -1)
    idc.AddConstEx(id, "HvCpuIdFunctionMsHvSvmFeatures", 0x40000008, -1)
    #https://patchwork.kernel.org/patch/10649047/
    idc.AddConstEx(id, "HvCpuIdFunctionNestedFeatures", 0x4000000A, -1)




    # ------------------------------------------------------------------------------------- #
    # Exit Reasons
    # ------------------------------------------------------------------------------------- #
    id = idc.AddEnum(0, "IA32_VMX_EXIT_REASONS_ENUM", idaapi.hexflag())
    idc.AddConstEx(id, "EXIT_REASON_EXCEPTION_NMI", 0x0, -1)
    idc.AddConstEx(id, "EXIT_REASON_EXTERNAL_INTERRUPT", 0x1, -1)
    idc.AddConstEx(id, "EXIT_REASON_TRIPLE_FAULT", 0x2, -1)
    idc.AddConstEx(id, "EXIT_REASON_INIT", 0x3, -1)
    idc.AddConstEx(id, "EXIT_REASON_SIPI", 0x4, -1)
    idc.AddConstEx(id, "EXIT_REASON_IO_SMI", 0x5, -1)
    idc.AddConstEx(id, "EXIT_REASON_OTHER_SMI", 0x6, -1)
    idc.AddConstEx(id, "EXIT_REASON_PENDING_VIRT_INTR", 0x7, -1)
    idc.AddConstEx(id, "EXIT_REASON_PENDING_VIRT_NMI",  0x8, -1)
    idc.AddConstEx(id, "EXIT_REASON_TASK_SWITCH", 0x9, -1)
    idc.AddConstEx(id, "EXIT_REASON_CPUID", 0x0A, -1)
    idc.AddConstEx(id, "EXIT_REASON_GETSEC", 0x0B, -1)
    idc.AddConstEx(id, "EXIT_REASON_HLT", 0x0C, -1)
    idc.AddConstEx(id, "EXIT_REASON_INVD", 0x0D, -1)
    idc.AddConstEx(id, "EXIT_REASON_INVLPG", 0x0E, -1)
    idc.AddConstEx(id, "EXIT_REASON_RDPMC", 0x0F, -1)
    idc.AddConstEx(id, "EXIT_REASON_RDTSC", 0x10, -1)
    idc.AddConstEx(id, "EXIT_REASON_RSM", 0x11, -1)
    idc.AddConstEx(id, "EXIT_REASON_VMCALL", 0x12, -1)
    idc.AddConstEx(id, "EXIT_REASON_VMCLEAR", 0x13, -1)
    idc.AddConstEx(id, "EXIT_REASON_VMLAUNCH", 0x14, -1)
    idc.AddConstEx(id, "EXIT_REASON_VMPTRLD", 0x15, -1)
    idc.AddConstEx(id, "EXIT_REASON_VMPTRST", 0x16, -1)
    idc.AddConstEx(id, "EXIT_REASON_VMREAD", 0x17, -1)
    idc.AddConstEx(id, "EXIT_REASON_VMRESUME", 0x18, -1)
    idc.AddConstEx(id, "EXIT_REASON_VMWRITE", 0x19, -1)
    idc.AddConstEx(id, "EXIT_REASON_VMXOFF", 0x1A, -1)
    idc.AddConstEx(id, "EXIT_REASON_VMXON", 0x1B, -1)
    idc.AddConstEx(id, "EXIT_REASON_CR_ACCESS", 0x1C, -1)
    idc.AddConstEx(id, "EXIT_REASON_DR_ACCESS", 0x1D, -1)
    idc.AddConstEx(id, "EXIT_REASON_IO_INSTRUCTION", 0x1E, -1)
    idc.AddConstEx(id, "EXIT_REASON_MSR_READ", 0x1F, -1)
    idc.AddConstEx(id, "EXIT_REASON_MSR_WRITE", 0x20, -1)
    idc.AddConstEx(id, "EXIT_REASON_INVALID_GUEST_STATE", 0X21, -1)
    idc.AddConstEx(id, "EXIT_REASON_MSR_LOADING", 0x22, -1)

    idc.AddConstEx(id, "EXIT_REASON_MWAIT_INSTRUCTION", 0x24, -1)
    idc.AddConstEx(id, "EXIT_REASON_MONITOR_TRAP_FLAG", 0x25, -1)

    idc.AddConstEx(id, "EXIT_REASON_MONITOR_INSTRUCTION", 0x27, -1)
    idc.AddConstEx(id, "EXIT_REASON_PAUSE_INSTRUCTION", 0x28, -1)
    idc.AddConstEx(id, "EXIT_REASON_MCE_DURING_VMENTRY", 0x29, -1)

    idc.AddConstEx(id, "EXIT_REASON_TPR_BELOW_THRESHOLD", 0x2B, -1)
    idc.AddConstEx(id, "EXIT_REASON_APIC_ACCESS", 0x2C, -1)
    idc.AddConstEx(id, "EXIT_REASON_VIRTUALIZED_EOI", 0x2D, -1)
    idc.AddConstEx(id, "EXIT_REASON_ACCESS_GDTR_OR_IDTR", 0x2E, -1)
    idc.AddConstEx(id, "EXIT_REASON_ACCESS_LDTR_OR_TR", 0x2F, -1)
    idc.AddConstEx(id, "EXIT_REASON_EPT_VIOLATION", 0x30, -1)
    idc.AddConstEx(id, "EXIT_REASON_EPT_MISCONFIG", 0x31, -1)
    idc.AddConstEx(id, "EXIT_REASON_INVEPT", 0x32, -1)
    idc.AddConstEx(id, "EXIT_REASON_RDTSCP", 0x33, -1)
    idc.AddConstEx(id, "EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED", 0x34, -1)
    idc.AddConstEx(id, "EXIT_REASON_INVVPID", 0x35, -1)
    idc.AddConstEx(id, "EXIT_REASON_WBINVD", 0x36, -1)
    idc.AddConstEx(id, "EXIT_REASON_XSETBV", 0x37, -1)
    idc.AddConstEx(id, "EXIT_REASON_APIC_WRITE", 0x38, -1)
    idc.AddConstEx(id, "EXIT_REASON_RDRAND", 0x39, -1)
    idc.AddConstEx(id, "EXIT_REASON_INVPCID", 0x3A, -1)
    idc.AddConstEx(id, "EXIT_REASON_EXECUTE_VMFUNC", 0x3B, -1)
    idc.AddConstEx(id, "EXIT_REASON_EXECUTE_ENCLS", 0x3C, -1)
    idc.AddConstEx(id, "EXIT_REASON_RDSEED", 0x3D, -1)
    idc.AddConstEx(id, "EXIT_REASON_PML_FULL", 0x3E, -1)
    idc.AddConstEx(id, "EXIT_REASON_XSAVES", 0x3F, -1)
    idc.AddConstEx(id, "EXIT_REASON_XRSTORS", 0x40, -1)
    idc.AddConstEx(id, "EXIT_REASON_PCOMMIT", 0x41, -1)

    # ------------------------------------------------------------------------------------- #
    # MSR
    # ------------------------------------------------------------------------------------- #
    id = idc.AddEnum(0, "IA32_MSR_LIST_ENUM", idaapi.hexflag())
    idc.AddConstEx(id, "HV_X64_MSR_GUEST_OS_ID", 0x40000000, -1)
    idc.AddConstEx(id, "HV_X64_MSR_HYPERCALL", 0x40000001, -1)
    idc.AddConstEx(id, "HV_X64_MSR_VP_INDEX", 0x40000002, -1)
    idc.AddConstEx(id, "HV_X64_MSR_RESET", 0x40000003, -1)
    idc.AddConstEx(id, "HV_X64_MSR_VP_RUNTIME", 0x40000010, -1)
    idc.AddConstEx(id, "HV_X64_MSR_TIME_REF_COUNT", 0x40000020, -1)
    idc.AddConstEx(id, "HV_X64_MSR_REFERENCE_TSC", 0x40000021, -1)
    idc.AddConstEx(id, "HV_X64_MSR_TSC_FREQUENCY", 0x40000022, -1)
    idc.AddConstEx(id, "HV_X64_MSR_APIC_FREQUENCY", 0x40000023, -1)
    idc.AddConstEx(id, "HV_X64_MSR_EOI", 0x40000070, -1)
    idc.AddConstEx(id, "HV_X64_MSR_ICR", 0x40000071, -1)
    idc.AddConstEx(id, "HV_X64_MSR_TPR", 0x40000072, -1)
    idc.AddConstEx(id, "HV_X64_MSR_VP_ASSIST_PAGE", 0x40000073, -1)
    idc.AddConstEx(id, "HV_X64_MSR_SCONTROL", 0x40000080, -1)
    idc.AddConstEx(id, "HV_X64_MSR_SVERSION", 0x40000081, -1)
    idc.AddConstEx(id, "HV_X64_MSR_SIEFP", 0x40000082, -1)
    idc.AddConstEx(id, "HV_X64_MSR_SIMP", 0x40000083, -1)
    idc.AddConstEx(id, "HV_X64_MSR_EOM", 0x40000084, -1)
    idc.AddConstEx(id, "HV_X64_MSR_SINT0", 0x40000090, -1)
    idc.AddConstEx(id, "HV_X64_MSR_SINT1", 0x40000091, -1)
    idc.AddConstEx(id, "HV_X64_MSR_SINT2", 0x40000092, -1)
    idc.AddConstEx(id, "HV_X64_MSR_SINT3", 0x40000093, -1)
    idc.AddConstEx(id, "HV_X64_MSR_SINT4", 0x40000094, -1)
    idc.AddConstEx(id, "HV_X64_MSR_SINT5", 0x40000095, -1)
    idc.AddConstEx(id, "HV_X64_MSR_SINT6", 0x40000096, -1)
    idc.AddConstEx(id, "HV_X64_MSR_SINT7", 0x40000097, -1)
    idc.AddConstEx(id, "HV_X64_MSR_SINT8", 0x40000098, -1)
    idc.AddConstEx(id, "HV_X64_MSR_SINT9", 0x40000099, -1)
    idc.AddConstEx(id, "HV_X64_MSR_SINT10", 0x4000009a, -1)
    idc.AddConstEx(id, "HV_X64_MSR_SINT11", 0x4000009b, -1)
    idc.AddConstEx(id, "HV_X64_MSR_SINT12", 0x4000009c, -1)
    idc.AddConstEx(id, "HV_X64_MSR_SINT13", 0x4000009d, -1)
    idc.AddConstEx(id, "HV_X64_MSR_SINT14", 0x4000009e, -1)
    idc.AddConstEx(id, "HV_X64_MSR_SINT15", 0x4000009f, -1)
    idc.AddConstEx(id, "HV_X64_MSR_STIMER0_CONFIG", 0x400000b0, -1)
    idc.AddConstEx(id, "HV_X64_MSR_STIMER0_COUNT", 0x400000b1, -1)
    idc.AddConstEx(id, "HV_X64_MSR_STIMER1_CONFIG", 0x400000b2, -1)
    idc.AddConstEx(id, "HV_X64_MSR_STIMER1_COUNT", 0x400000b3, -1)
    idc.AddConstEx(id, "HV_X64_MSR_STIMER2_CONFIG", 0x400000b4, -1)
    idc.AddConstEx(id, "HV_X64_MSR_STIMER2_COUNT", 0x400000b5, -1)
    idc.AddConstEx(id, "HV_X64_MSR_STIMER3_CONFIG", 0x400000b6, -1)
    idc.AddConstEx(id, "HV_X64_MSR_STIMER3_COUNT", 0x400000b7, -1)
    idc.AddConstEx(id, "HV_X64_MSR_POWER_STATE_TRIGGER_C1", 0x400000c1, -1)
    idc.AddConstEx(id, "HV_X64_MSR_POWER_STATE_TRIGGER_C2", 0x400000c2, -1)
    idc.AddConstEx(id, "HV_X64_MSR_POWER_STATE_TRIGGER_C3", 0x400000c3, -1)
    idc.AddConstEx(id, "HV_X64_MSR_POWER_STATE_CONFIG_C1", 0x400000d1, -1)
    idc.AddConstEx(id, "HV_X64_MSR_POWER_STATE_CONFIG_C2", 0x400000d2, -1)
    idc.AddConstEx(id, "HV_X64_MSR_POWER_STATE_CONFIG_C3", 0x400000d3, -1)
    idc.AddConstEx(id, "HV_X64_MSR_STATS_PARTITION_RETAIL_PAGE", 0x400000e0, -1)
    idc.AddConstEx(id, "HV_X64_MSR_STATS_PARTITION_INTERNAL_PAGE", 0x400000e1, -1)
    idc.AddConstEx(id, "HV_X64_MSR_STATS_VP_RETAIL_PAGE", 0x400000e2, -1)
    idc.AddConstEx(id, "HV_X64_MSR_STATS_VP_INTERNAL_PAGE", 0x400000e3, -1)
    idc.AddConstEx(id, "HV_X64_MSR_GUEST_IDLE", 0x400000f0, -1)
    idc.AddConstEx(id, "HV_X64_MSR_SYNTH_DEBUG_CONTROL", 0x400000f1, -1)
    idc.AddConstEx(id, "HV_X64_MSR_SYNTH_DEBUG_STATUS", 0x400000f2, -1)
    idc.AddConstEx(id, "HV_X64_MSR_SYNTH_DEBUG_SEND_BUFFER", 0x400000f3, -1)
    idc.AddConstEx(id, "HV_X64_MSR_SYNTH_DEBUG_RECEIVE_BUFFER", 0x400000f4, -1)
    idc.AddConstEx(id, "HV_X64_MSR_SYNTH_DEBUG_PENDING_BUFFER", 0x400000f5, -1)
    idc.AddConstEx(id, "HV_X64_MSR_CRASH_P0", 0x40000100, -1)
    idc.AddConstEx(id, "HV_X64_MSR_CRASH_P1", 0x40000101, -1)
    idc.AddConstEx(id, "HV_X64_MSR_CRASH_P2", 0x40000102, -1)
    idc.AddConstEx(id, "HV_X64_MSR_CRASH_P3", 0x40000103, -1)
    idc.AddConstEx(id, "HV_X64_MSR_CRASH_P4", 0x40000104, -1)
    idc.AddConstEx(id, "HV_X64_MSR_CRASH_CTL", 0x40000105, -1)
    idc.AddConstEx(id, "HV_X64_MSR_REENLIGHTENMENT_CONTROL", 0x40000106, -1)
    idc.AddConstEx(id, "HV_X64_MSR_TSC_EMULATION_CONTROL", 0x40000107, -1)
    idc.AddConstEx(id, "HV_X64_MSR_TSC_EMULATION_STATUS", 0x40000108, -1)
    idc.AddConstEx(id, "MSR_XEON_D_PPIN_CTL", 0x4e, -1)
    idc.AddConstEx(id, "MSR_XEON_D_PPIN", 0x4f, -1)
    idc.AddConstEx(id, "MSR_XEON_D_PLATFORM_INFO", 0xce, -1)
    idc.AddConstEx(id, "MSR_XEON_D_PKG_CST_CONFIG_CONTROL", 0xe2, -1)
    idc.AddConstEx(id, "IA32_MCG_CAP", 0x179, -1)
    idc.AddConstEx(id, "MSR_XEON_D_SMM_MCA_CAP", 0x17d, -1)
    idc.AddConstEx(id, "MSR_XEON_D_TEMPERATURE_TARGET", 0x1a2, -1)
    idc.AddConstEx(id, "MSR_XEON_D_TURBO_RATIO_LIMIT", 0x1ad, -1)
    idc.AddConstEx(id, "MSR_XEON_D_TURBO_RATIO_LIMIT1", 0x1ae, -1)
    idc.AddConstEx(id, "MSR_XEON_D_RAPL_POWER_UNIT", 0x606, -1)
    idc.AddConstEx(id, "MSR_XEON_D_DRAM_POWER_LIMIT", 0x618, -1)
    idc.AddConstEx(id, "MSR_XEON_D_DRAM_ENERGY_STATUS", 0x619, -1)
    idc.AddConstEx(id, "MSR_XEON_D_DRAM_PERF_STATUS", 0x61b, -1)
    idc.AddConstEx(id, "MSR_XEON_D_DRAM_POWER_INFO", 0x61c, -1)
    idc.AddConstEx(id, "MSR_XEON_D_MSRUNCORE_RATIO_LIMIT", 0x620, -1)
    idc.AddConstEx(id, "MSR_XEON_D_PP0_ENERGY_STATUS", 0x639, -1)
    idc.AddConstEx(id, "MSR_XEON_D_CORE_PERF_LIMIT_REASONS", 0x690, -1)
    idc.AddConstEx(id, "IA32_QM_EVTSEL", 0xc8d, -1)
    idc.AddConstEx(id, "IA32_PQR_ASSOC", 0xc8f, -1)
    idc.AddConstEx(id, "MSR_XEON_D_TURBO_RATIO_LIMIT3", 0x1ac, -1)
    idc.AddConstEx(id, "IA32_L3_QOS_CFG", 0xc81, -1)
    idc.AddConstEx(id, "MSR_XEON_D_IA32_L3_QOS_MASK_0", 0xc90, -1)
    idc.AddConstEx(id, "MSR_XEON_D_IA32_L3_QOS_MASK_1", 0xc91, -1)
    idc.AddConstEx(id, "MSR_XEON_D_IA32_L3_QOS_MASK_2", 0xc92, -1)
    idc.AddConstEx(id, "MSR_XEON_D_IA32_L3_QOS_MASK_3", 0xc93, -1)
    idc.AddConstEx(id, "MSR_XEON_D_IA32_L3_QOS_MASK_4", 0xc94, -1)
    idc.AddConstEx(id, "MSR_XEON_D_IA32_L3_QOS_MASK_5", 0xc95, -1)
    idc.AddConstEx(id, "MSR_XEON_D_IA32_L3_QOS_MASK_6", 0xc96, -1)
    idc.AddConstEx(id, "MSR_XEON_D_IA32_L3_QOS_MASK_7", 0xc97, -1)
    idc.AddConstEx(id, "MSR_XEON_D_IA32_L3_QOS_MASK_8", 0xc98, -1)
    idc.AddConstEx(id, "MSR_XEON_D_IA32_L3_QOS_MASK_9", 0xc99, -1)
    idc.AddConstEx(id, "MSR_XEON_D_IA32_L3_QOS_MASK_10", 0xc9a, -1)
    idc.AddConstEx(id, "MSR_XEON_D_IA32_L3_QOS_MASK_11", 0xc9b, -1)
    idc.AddConstEx(id, "MSR_XEON_D_IA32_L3_QOS_MASK_12", 0xc9c, -1)
    idc.AddConstEx(id, "MSR_XEON_D_IA32_L3_QOS_MASK_13", 0xc9d, -1)
    idc.AddConstEx(id, "MSR_XEON_D_IA32_L3_QOS_MASK_14", 0xc9e, -1)
    idc.AddConstEx(id, "MSR_XEON_D_IA32_L3_QOS_MASK_15", 0xc9f, -1)
    idc.AddConstEx(id, "MSR_SPEC_CTRL", 0x48, -1)
    idc.AddConstEx(id, "MSR_PRED_CMD", 0x49, -1)
    idc.AddConstEx(id, "MSR_LBR_SELECT", 0x1c8, -1)
    idc.AddConstEx(id, "MSR_LBR_TOS", 0x1c9, -1)
    idc.AddConstEx(id, "MSR_LBR_NHM_FROM", 0x680, -1)
    idc.AddConstEx(id, "MSR_LBR_NHM_TO", 0x6c0, -1)
    idc.AddConstEx(id, "MSR_LBR_CORE_FROM", 0x40, -1)
    idc.AddConstEx(id, "MSR_LBR_CORE_TO", 0x60, -1)
    idc.AddConstEx(id, "MSR_IA32_LASTBRANCHFROMIP", 0x1db, -1)
    idc.AddConstEx(id, "MSR_IA32_LASTBRANCHTOIP", 0x1dc, -1)
    idc.AddConstEx(id, "MSR_IA32_LASTINTFROMIP", 0x1dd, -1)
    idc.AddConstEx(id, "MSR_IA32_LASTINTTOIP", 0x1de, -1)
    idc.AddConstEx(id, "MSR_PKG_C3_RESIDENCY", 0x3f8, -1)
    idc.AddConstEx(id, "MSR_PKG_C6_RESIDENCY", 0x3f9, -1)
    idc.AddConstEx(id, "MSR_PKG_C7_RESIDENCY", 0x3fa, -1)
    idc.AddConstEx(id, "MSR_CORE_C3_RESIDENCY", 0x3fc, -1)
    idc.AddConstEx(id, "MSR_CORE_C6_RESIDENCY", 0x3fd, -1)
    idc.AddConstEx(id, "MSR_CORE_C7_RESIDENCY", 0x3fe, -1)
    idc.AddConstEx(id, "MSR_KNL_CORE_C6_RESIDENCY", 0x3ff, -1)
    idc.AddConstEx(id, "MSR_PKG_C2_RESIDENCY", 0x60d, -1)
    idc.AddConstEx(id, "MSR_PKG_C8_RESIDENCY", 0x630, -1)
    idc.AddConstEx(id, "MSR_PKG_C9_RESIDENCY", 0x631, -1)
    idc.AddConstEx(id, "MSR_PKG_C10_RESIDENCY", 0x632, -1)
    idc.AddConstEx(id, "MSR_IDT_FCR1", 0x107, -1)
    idc.AddConstEx(id, "MSR_IDT_FCR2", 0x108, -1)
    idc.AddConstEx(id, "MSR_IDT_FCR3", 0x109, -1)
    idc.AddConstEx(id, "MSR_IDT_FCR4", 0x10a, -1)
    idc.AddConstEx(id, "MSR_IDT_MCR0", 0x110, -1)
    idc.AddConstEx(id, "MSR_IDT_MCR1", 0x111, -1)
    idc.AddConstEx(id, "MSR_IDT_MCR2", 0x112, -1)
    idc.AddConstEx(id, "MSR_IDT_MCR3", 0x113, -1)
    idc.AddConstEx(id, "MSR_IDT_MCR4", 0x114, -1)
    idc.AddConstEx(id, "MSR_IDT_MCR5", 0x115, -1)
    idc.AddConstEx(id, "MSR_IDT_MCR6", 0x116, -1)
    idc.AddConstEx(id, "MSR_IDT_MCR7", 0x117, -1)
    idc.AddConstEx(id, "MSR_IDT_MCR_CTRL", 0x120, -1)
    idc.AddConstEx(id, "MSR_FSB_FREQ", 0xcd, -1)
    idc.AddConstEx(id, "MSR_IA32_BBL_CR_CTL", 0x119, -1)
    idc.AddConstEx(id, "MSR_VM_CR", 0xc0010114, -1)
    idc.AddConstEx(id, "MSR_VM_IGNNE", 0xc0010115, -1)
    idc.AddConstEx(id, "MSR_VM_HSAVE_PA", 0xc0010117, -1)
    idc.AddConstEx(id, "IA32_MTRR_FIX64K_BASE", 0x0, -1)
    idc.AddConstEx(id, "IA32_P5_MC_TYPE", 0x1, -1)
    idc.AddConstEx(id, "IA32_MONITOR_FILTER_SIZE", 0x6, -1)
    idc.AddConstEx(id, "IA32_TIME_STAMP_COUNTER", 0x10, -1)
    idc.AddConstEx(id, "IA32_PLATFORM_ID", 0x17, -1)
    idc.AddConstEx(id, "IA32_APIC_BASE", 0x1b, -1)
    idc.AddConstEx(id, "IA32_FEATURE_CONTROL", 0x3a, -1)
    idc.AddConstEx(id, "IA32_TSC_ADJUST", 0x3b, -1)
    idc.AddConstEx(id, "IA32_BIOS_UPDT_TRIG", 0x79, -1)
    idc.AddConstEx(id, "IA32_BIOS_SIGN_ID", 0x8b, -1)
    idc.AddConstEx(id, "IA32_SGXLEPUBKEYHASH0", 0x8c, -1)
    idc.AddConstEx(id, "IA32_SGXLEPUBKEYHASH1", 0x8d, -1)
    idc.AddConstEx(id, "IA32_SGXLEPUBKEYHASH2", 0x8e, -1)
    idc.AddConstEx(id, "IA32_SGXLEPUBKEYHASH3", 0x8f, -1)
    idc.AddConstEx(id, "IA32_SMM_MONITOR_CTL", 0x9b, -1)
    idc.AddConstEx(id, "IA32_SMBASE", 0x9e, -1)
    idc.AddConstEx(id, "IA32_PMC0", 0xc1, -1)
    idc.AddConstEx(id, "IA32_PMC1", 0xc2, -1)
    idc.AddConstEx(id, "IA32_PMC2", 0xc3, -1)
    idc.AddConstEx(id, "IA32_PMC3", 0xc4, -1)
    idc.AddConstEx(id, "IA32_PMC4", 0xc5, -1)
    idc.AddConstEx(id, "IA32_PMC5", 0xc6, -1)
    idc.AddConstEx(id, "IA32_PMC6", 0xc7, -1)
    idc.AddConstEx(id, "IA32_PMC7", 0xc8, -1)
    idc.AddConstEx(id, "IA32_MPERF", 0xe7, -1)
    idc.AddConstEx(id, "IA32_APERF", 0xe8, -1)
    idc.AddConstEx(id, "IA32_MTRRCAP", 0xfe, -1)
    idc.AddConstEx(id, "IA32_SYSENTER_CS", 0x174, -1)
    idc.AddConstEx(id, "IA32_SYSENTER_ESP", 0x175, -1)
    idc.AddConstEx(id, "IA32_SYSENTER_EIP", 0x176, -1)
    idc.AddConstEx(id, "IA32_MCG_STATUS", 0x17a, -1)
    idc.AddConstEx(id, "IA32_MCG_CTL", 0x17b, -1)
    idc.AddConstEx(id, "IA32_PERFEVTSEL0", 0x186, -1)
    idc.AddConstEx(id, "IA32_PERFEVTSEL1", 0x187, -1)
    idc.AddConstEx(id, "IA32_PERFEVTSEL2", 0x188, -1)
    idc.AddConstEx(id, "IA32_PERFEVTSEL3", 0x189, -1)
    idc.AddConstEx(id, "IA32_PERF_STATUS", 0x198, -1)
    idc.AddConstEx(id, "IA32_PERF_CTL", 0x199, -1)
    idc.AddConstEx(id, "IA32_CLOCK_MODULATION", 0x19a, -1)
    idc.AddConstEx(id, "IA32_THERM_INTERRUPT", 0x19b, -1)
    idc.AddConstEx(id, "IA32_THERM_STATUS", 0x19c, -1)
    idc.AddConstEx(id, "IA32_MISC_ENABLE", 0x1a0, -1)
    idc.AddConstEx(id, "IA32_ENERGY_PERF_BIAS", 0x1b0, -1)
    idc.AddConstEx(id, "IA32_PACKAGE_THERM_STATUS", 0x1b1, -1)
    idc.AddConstEx(id, "IA32_PACKAGE_THERM_INTERRUPT", 0x1b2, -1)
    idc.AddConstEx(id, "IA32_DEBUGCTL", 0x1d9, -1)
    idc.AddConstEx(id, "IA32_SMRR_PHYSBASE", 0x1f2, -1)
    idc.AddConstEx(id, "IA32_SMRR_PHYSMASK", 0x1f3, -1)
    idc.AddConstEx(id, "IA32_PLATFORM_DCA_CAP", 0x1f8, -1)
    idc.AddConstEx(id, "IA32_CPU_DCA_CAP", 0x1f9, -1)
    idc.AddConstEx(id, "IA32_DCA_0_CAP", 0x1fa, -1)
    idc.AddConstEx(id, "IA32_MTRR_PHYSBASE0", 0x200, -1)
    idc.AddConstEx(id, "IA32_MTRR_PHYSBASE1", 0x202, -1)
    idc.AddConstEx(id, "IA32_MTRR_PHYSBASE2", 0x204, -1)
    idc.AddConstEx(id, "IA32_MTRR_PHYSBASE3", 0x206, -1)
    idc.AddConstEx(id, "IA32_MTRR_PHYSBASE4", 0x208, -1)
    idc.AddConstEx(id, "IA32_MTRR_PHYSBASE5", 0x20a, -1)
    idc.AddConstEx(id, "IA32_MTRR_PHYSBASE6", 0x20c, -1)
    idc.AddConstEx(id, "IA32_MTRR_PHYSBASE7", 0x20e, -1)
    idc.AddConstEx(id, "IA32_MTRR_PHYSBASE8", 0x210, -1)
    idc.AddConstEx(id, "IA32_MTRR_PHYSBASE9", 0x212, -1)
    idc.AddConstEx(id, "IA32_MTRR_PHYSMASK0", 0x201, -1)
    idc.AddConstEx(id, "IA32_MTRR_PHYSMASK1", 0x203, -1)
    idc.AddConstEx(id, "IA32_MTRR_PHYSMASK2", 0x205, -1)
    idc.AddConstEx(id, "IA32_MTRR_PHYSMASK3", 0x207, -1)
    idc.AddConstEx(id, "IA32_MTRR_PHYSMASK4", 0x209, -1)
    idc.AddConstEx(id, "IA32_MTRR_PHYSMASK5", 0x20b, -1)
    idc.AddConstEx(id, "IA32_MTRR_PHYSMASK6", 0x20d, -1)
    idc.AddConstEx(id, "IA32_MTRR_PHYSMASK7", 0x20f, -1)
    idc.AddConstEx(id, "IA32_MTRR_PHYSMASK8", 0x211, -1)
    idc.AddConstEx(id, "IA32_MTRR_PHYSMASK9", 0x213, -1)
    idc.AddConstEx(id, "IA32_MTRR_FIX64K_SIZE", 0x10000, -1)
    idc.AddConstEx(id, "IA32_MTRR_FIX64K_00000", 0x250, -1)
    idc.AddConstEx(id, "IA32_MTRR_FIX16K_BASE", 0x80000, -1)
    idc.AddConstEx(id, "IA32_MTRR_FIX16K_SIZE", 0x4000, -1)
    idc.AddConstEx(id, "IA32_MTRR_FIX16K_80000", 0x258, -1)
    idc.AddConstEx(id, "IA32_MTRR_FIX16K_A0000", 0x259, -1)
    idc.AddConstEx(id, "IA32_MTRR_FIX4K_BASE", 0xc0000, -1)
    idc.AddConstEx(id, "IA32_MTRR_FIX4K_SIZE", 0x1000, -1)
    idc.AddConstEx(id, "IA32_MTRR_FIX4K_C0000", 0x268, -1)
    idc.AddConstEx(id, "IA32_MTRR_FIX4K_C8000", 0x269, -1)
    idc.AddConstEx(id, "IA32_MTRR_FIX4K_D0000", 0x26a, -1)
    idc.AddConstEx(id, "IA32_MTRR_FIX4K_D8000", 0x26b, -1)
    idc.AddConstEx(id, "IA32_MTRR_FIX4K_E0000", 0x26c, -1)
    idc.AddConstEx(id, "IA32_MTRR_FIX4K_E8000", 0x26d, -1)
    idc.AddConstEx(id, "IA32_MTRR_FIX4K_F0000", 0x26e, -1)
    idc.AddConstEx(id, "IA32_MTRR_FIX4K_F8000", 0x26f, -1)
    idc.AddConstEx(id, "IA32_MTRR_FIX_COUNT", 0x58, -1)
    idc.AddConstEx(id, "IA32_MTRR_VARIABLE_COUNT", 0xff, -1)
    idc.AddConstEx(id, "IA32_MTRR_COUNT", 0x157, -1)
    idc.AddConstEx(id, "IA32_PAT", 0x277, -1)
    idc.AddConstEx(id, "IA32_MC0_CTL2", 0x280, -1)
    idc.AddConstEx(id, "IA32_MC1_CTL2", 0x281, -1)
    idc.AddConstEx(id, "IA32_MC2_CTL2", 0x282, -1)
    idc.AddConstEx(id, "IA32_MC3_CTL2", 0x283, -1)
    idc.AddConstEx(id, "IA32_MC4_CTL2", 0x284, -1)
    idc.AddConstEx(id, "IA32_MC5_CTL2", 0x285, -1)
    idc.AddConstEx(id, "IA32_MC6_CTL2", 0x286, -1)
    idc.AddConstEx(id, "IA32_MC7_CTL2", 0x287, -1)
    idc.AddConstEx(id, "IA32_MC8_CTL2", 0x288, -1)
    idc.AddConstEx(id, "IA32_MC9_CTL2", 0x289, -1)
    idc.AddConstEx(id, "IA32_MC10_CTL2", 0x28a, -1)
    idc.AddConstEx(id, "IA32_MC11_CTL2", 0x28b, -1)
    idc.AddConstEx(id, "IA32_MC12_CTL2", 0x28c, -1)
    idc.AddConstEx(id, "IA32_MC13_CTL2", 0x28d, -1)
    idc.AddConstEx(id, "IA32_MC14_CTL2", 0x28e, -1)
    idc.AddConstEx(id, "IA32_MC15_CTL2", 0x28f, -1)
    idc.AddConstEx(id, "IA32_MC16_CTL2", 0x290, -1)
    idc.AddConstEx(id, "IA32_MC17_CTL2", 0x291, -1)
    idc.AddConstEx(id, "IA32_MC18_CTL2", 0x292, -1)
    idc.AddConstEx(id, "IA32_MC19_CTL2", 0x293, -1)
    idc.AddConstEx(id, "IA32_MC20_CTL2", 0x294, -1)
    idc.AddConstEx(id, "IA32_MC21_CTL2", 0x295, -1)
    idc.AddConstEx(id, "IA32_MC22_CTL2", 0x296, -1)
    idc.AddConstEx(id, "IA32_MC23_CTL2", 0x297, -1)
    idc.AddConstEx(id, "IA32_MC24_CTL2", 0x298, -1)
    idc.AddConstEx(id, "IA32_MC25_CTL2", 0x299, -1)
    idc.AddConstEx(id, "IA32_MC26_CTL2", 0x29a, -1)
    idc.AddConstEx(id, "IA32_MC27_CTL2", 0x29b, -1)
    idc.AddConstEx(id, "IA32_MC28_CTL2", 0x29c, -1)
    idc.AddConstEx(id, "IA32_MC29_CTL2", 0x29d, -1)
    idc.AddConstEx(id, "IA32_MC30_CTL2", 0x29e, -1)
    idc.AddConstEx(id, "IA32_MC31_CTL2", 0x29f, -1)
    idc.AddConstEx(id, "IA32_MTRR_DEF_TYPE", 0x2ff, -1)
    idc.AddConstEx(id, "IA32_FIXED_CTR0", 0x309, -1)
    idc.AddConstEx(id, "IA32_FIXED_CTR1", 0x30a, -1)
    idc.AddConstEx(id, "IA32_FIXED_CTR2", 0x30b, -1)
    idc.AddConstEx(id, "IA32_PERF_CAPABILITIES", 0x345, -1)
    idc.AddConstEx(id, "IA32_FIXED_CTR_CTRL", 0x38d, -1)
    idc.AddConstEx(id, "IA32_PERF_GLOBAL_STATUS", 0x38e, -1)
    idc.AddConstEx(id, "IA32_PERF_GLOBAL_CTRL", 0x38f, -1)
    idc.AddConstEx(id, "IA32_PERF_GLOBAL_STATUS_RESET", 0x390, -1)
    idc.AddConstEx(id, "IA32_PERF_GLOBAL_STATUS_SET", 0x391, -1)
    idc.AddConstEx(id, "IA32_PERF_GLOBAL_INUSE", 0x392, -1)
    idc.AddConstEx(id, "IA32_PEBS_ENABLE", 0x3f1, -1)
    idc.AddConstEx(id, "IA32_MC0_CTL", 0x400, -1)
    idc.AddConstEx(id, "IA32_MC1_CTL", 0x404, -1)
    idc.AddConstEx(id, "IA32_MC2_CTL", 0x408, -1)
    idc.AddConstEx(id, "IA32_MC3_CTL", 0x40c, -1)
    idc.AddConstEx(id, "IA32_MC4_CTL", 0x410, -1)
    idc.AddConstEx(id, "IA32_MC5_CTL", 0x414, -1)
    idc.AddConstEx(id, "IA32_MC6_CTL", 0x418, -1)
    idc.AddConstEx(id, "IA32_MC7_CTL", 0x41c, -1)
    idc.AddConstEx(id, "IA32_MC8_CTL", 0x420, -1)
    idc.AddConstEx(id, "IA32_MC9_CTL", 0x424, -1)
    idc.AddConstEx(id, "IA32_MC10_CTL", 0x428, -1)
    idc.AddConstEx(id, "IA32_MC11_CTL", 0x42c, -1)
    idc.AddConstEx(id, "IA32_MC12_CTL", 0x430, -1)
    idc.AddConstEx(id, "IA32_MC13_CTL", 0x434, -1)
    idc.AddConstEx(id, "IA32_MC14_CTL", 0x438, -1)
    idc.AddConstEx(id, "IA32_MC15_CTL", 0x43c, -1)
    idc.AddConstEx(id, "IA32_MC16_CTL", 0x440, -1)
    idc.AddConstEx(id, "IA32_MC17_CTL", 0x444, -1)
    idc.AddConstEx(id, "IA32_MC18_CTL", 0x448, -1)
    idc.AddConstEx(id, "IA32_MC19_CTL", 0x44c, -1)
    idc.AddConstEx(id, "IA32_MC20_CTL", 0x450, -1)
    idc.AddConstEx(id, "IA32_MC21_CTL", 0x454, -1)
    idc.AddConstEx(id, "IA32_MC22_CTL", 0x458, -1)
    idc.AddConstEx(id, "IA32_MC23_CTL", 0x45c, -1)
    idc.AddConstEx(id, "IA32_MC24_CTL", 0x460, -1)
    idc.AddConstEx(id, "IA32_MC25_CTL", 0x464, -1)
    idc.AddConstEx(id, "IA32_MC26_CTL", 0x468, -1)
    idc.AddConstEx(id, "IA32_MC27_CTL", 0x46c, -1)
    idc.AddConstEx(id, "IA32_MC28_CTL", 0x470, -1)
    idc.AddConstEx(id, "IA32_MC0_STATUS", 0x401, -1)
    idc.AddConstEx(id, "IA32_MC1_STATUS", 0x405, -1)
    idc.AddConstEx(id, "IA32_MC2_STATUS", 0x409, -1)
    idc.AddConstEx(id, "IA32_MC3_STATUS", 0x40d, -1)
    idc.AddConstEx(id, "IA32_MC4_STATUS", 0x411, -1)
    idc.AddConstEx(id, "IA32_MC5_STATUS", 0x415, -1)
    idc.AddConstEx(id, "IA32_MC6_STATUS", 0x419, -1)
    idc.AddConstEx(id, "IA32_MC7_STATUS", 0x41d, -1)
    idc.AddConstEx(id, "IA32_MC8_STATUS", 0x421, -1)
    idc.AddConstEx(id, "IA32_MC9_STATUS", 0x425, -1)
    idc.AddConstEx(id, "IA32_MC10_STATUS", 0x429, -1)
    idc.AddConstEx(id, "IA32_MC11_STATUS", 0x42d, -1)
    idc.AddConstEx(id, "IA32_MC12_STATUS", 0x431, -1)
    idc.AddConstEx(id, "IA32_MC13_STATUS", 0x435, -1)
    idc.AddConstEx(id, "IA32_MC14_STATUS", 0x439, -1)
    idc.AddConstEx(id, "IA32_MC15_STATUS", 0x43d, -1)
    idc.AddConstEx(id, "IA32_MC16_STATUS", 0x441, -1)
    idc.AddConstEx(id, "IA32_MC17_STATUS", 0x445, -1)
    idc.AddConstEx(id, "IA32_MC18_STATUS", 0x449, -1)
    idc.AddConstEx(id, "IA32_MC19_STATUS", 0x44d, -1)
    idc.AddConstEx(id, "IA32_MC20_STATUS", 0x451, -1)
    idc.AddConstEx(id, "IA32_MC21_STATUS", 0x455, -1)
    idc.AddConstEx(id, "IA32_MC22_STATUS", 0x459, -1)
    idc.AddConstEx(id, "IA32_MC23_STATUS", 0x45d, -1)
    idc.AddConstEx(id, "IA32_MC24_STATUS", 0x461, -1)
    idc.AddConstEx(id, "IA32_MC25_STATUS", 0x465, -1)
    idc.AddConstEx(id, "IA32_MC26_STATUS", 0x469, -1)
    idc.AddConstEx(id, "IA32_MC27_STATUS", 0x46d, -1)
    idc.AddConstEx(id, "IA32_MC28_STATUS", 0x471, -1)
    idc.AddConstEx(id, "IA32_MC0_ADDR", 0x402, -1)
    idc.AddConstEx(id, "IA32_MC1_ADDR", 0x406, -1)
    idc.AddConstEx(id, "IA32_MC2_ADDR", 0x40a, -1)
    idc.AddConstEx(id, "IA32_MC3_ADDR", 0x40e, -1)
    idc.AddConstEx(id, "IA32_MC4_ADDR", 0x412, -1)
    idc.AddConstEx(id, "IA32_MC5_ADDR", 0x416, -1)
    idc.AddConstEx(id, "IA32_MC6_ADDR", 0x41a, -1)
    idc.AddConstEx(id, "IA32_MC7_ADDR", 0x41e, -1)
    idc.AddConstEx(id, "IA32_MC8_ADDR", 0x422, -1)
    idc.AddConstEx(id, "IA32_MC9_ADDR", 0x426, -1)
    idc.AddConstEx(id, "IA32_MC10_ADDR", 0x42a, -1)
    idc.AddConstEx(id, "IA32_MC11_ADDR", 0x42e, -1)
    idc.AddConstEx(id, "IA32_MC12_ADDR", 0x432, -1)
    idc.AddConstEx(id, "IA32_MC13_ADDR", 0x436, -1)
    idc.AddConstEx(id, "IA32_MC14_ADDR", 0x43a, -1)
    idc.AddConstEx(id, "IA32_MC15_ADDR", 0x43e, -1)
    idc.AddConstEx(id, "IA32_MC16_ADDR", 0x442, -1)
    idc.AddConstEx(id, "IA32_MC17_ADDR", 0x446, -1)
    idc.AddConstEx(id, "IA32_MC18_ADDR", 0x44a, -1)
    idc.AddConstEx(id, "IA32_MC19_ADDR", 0x44e, -1)
    idc.AddConstEx(id, "IA32_MC20_ADDR", 0x452, -1)
    idc.AddConstEx(id, "IA32_MC21_ADDR", 0x456, -1)
    idc.AddConstEx(id, "IA32_MC22_ADDR", 0x45a, -1)
    idc.AddConstEx(id, "IA32_MC23_ADDR", 0x45e, -1)
    idc.AddConstEx(id, "IA32_MC24_ADDR", 0x462, -1)
    idc.AddConstEx(id, "IA32_MC25_ADDR", 0x466, -1)
    idc.AddConstEx(id, "IA32_MC26_ADDR", 0x46a, -1)
    idc.AddConstEx(id, "IA32_MC27_ADDR", 0x46e, -1)
    idc.AddConstEx(id, "IA32_MC28_ADDR", 0x472, -1)
    idc.AddConstEx(id, "IA32_MC0_MISC", 0x403, -1)
    idc.AddConstEx(id, "IA32_MC1_MISC", 0x407, -1)
    idc.AddConstEx(id, "IA32_MC2_MISC", 0x40b, -1)
    idc.AddConstEx(id, "IA32_MC3_MISC", 0x40f, -1)
    idc.AddConstEx(id, "IA32_MC4_MISC", 0x413, -1)
    idc.AddConstEx(id, "IA32_MC5_MISC", 0x417, -1)
    idc.AddConstEx(id, "IA32_MC6_MISC", 0x41b, -1)
    idc.AddConstEx(id, "IA32_MC7_MISC", 0x41f, -1)
    idc.AddConstEx(id, "IA32_MC8_MISC", 0x423, -1)
    idc.AddConstEx(id, "IA32_MC9_MISC", 0x427, -1)
    idc.AddConstEx(id, "IA32_MC10_MISC", 0x42b, -1)
    idc.AddConstEx(id, "IA32_MC11_MISC", 0x42f, -1)
    idc.AddConstEx(id, "IA32_MC12_MISC", 0x433, -1)
    idc.AddConstEx(id, "IA32_MC13_MISC", 0x437, -1)
    idc.AddConstEx(id, "IA32_MC14_MISC", 0x43b, -1)
    idc.AddConstEx(id, "IA32_MC15_MISC", 0x43f, -1)
    idc.AddConstEx(id, "IA32_MC16_MISC", 0x443, -1)
    idc.AddConstEx(id, "IA32_MC17_MISC", 0x447, -1)
    idc.AddConstEx(id, "IA32_MC18_MISC", 0x44b, -1)
    idc.AddConstEx(id, "IA32_MC19_MISC", 0x44f, -1)
    idc.AddConstEx(id, "IA32_MC20_MISC", 0x453, -1)
    idc.AddConstEx(id, "IA32_MC21_MISC", 0x457, -1)
    idc.AddConstEx(id, "IA32_MC22_MISC", 0x45b, -1)
    idc.AddConstEx(id, "IA32_MC23_MISC", 0x45f, -1)
    idc.AddConstEx(id, "IA32_MC24_MISC", 0x463, -1)
    idc.AddConstEx(id, "IA32_MC25_MISC", 0x467, -1)
    idc.AddConstEx(id, "IA32_MC26_MISC", 0x46b, -1)
    idc.AddConstEx(id, "IA32_MC27_MISC", 0x46f, -1)
    idc.AddConstEx(id, "IA32_MC28_MISC", 0x473, -1)
    idc.AddConstEx(id, "IA32_VMX_BASIC", 0x480, -1)
    idc.AddConstEx(id, "IA32_VMX_PINBASED_CTLS", 0x481, -1)
    idc.AddConstEx(id, "IA32_VMX_PROCBASED_CTLS", 0x482, -1)
    idc.AddConstEx(id, "IA32_VMX_EXIT_CTLS", 0x483, -1)
    idc.AddConstEx(id, "IA32_VMX_ENTRY_CTLS", 0x484, -1)
    idc.AddConstEx(id, "IA32_VMX_MISC", 0x485, -1)
    idc.AddConstEx(id, "IA32_VMX_CR0_FIXED0", 0x486, -1)
    idc.AddConstEx(id, "IA32_VMX_CR0_FIXED1", 0x487, -1)
    idc.AddConstEx(id, "IA32_VMX_CR4_FIXED0", 0x488, -1)
    idc.AddConstEx(id, "IA32_VMX_CR4_FIXED1", 0x489, -1)
    idc.AddConstEx(id, "IA32_VMX_VMCS_ENUM", 0x48a, -1)
    idc.AddConstEx(id, "IA32_VMX_PROCBASED_CTLS2", 0x48b, -1)
    idc.AddConstEx(id, "IA32_VMX_EPT_VPID_CAP", 0x48c, -1)
    idc.AddConstEx(id, "IA32_VMX_TRUE_PINBASED_CTLS", 0x48d, -1)
    idc.AddConstEx(id, "IA32_VMX_TRUE_PROCBASED_CTLS", 0x48e, -1)
    idc.AddConstEx(id, "IA32_VMX_TRUE_EXIT_CTLS", 0x48f, -1)
    idc.AddConstEx(id, "IA32_VMX_TRUE_ENTRY_CTLS", 0x490, -1)
    idc.AddConstEx(id, "IA32_VMX_VMFUNC", 0x491, -1)
    idc.AddConstEx(id, "IA32_A_PMC0", 0x4c1, -1)
    idc.AddConstEx(id, "IA32_A_PMC1", 0x4c2, -1)
    idc.AddConstEx(id, "IA32_A_PMC2", 0x4c3, -1)
    idc.AddConstEx(id, "IA32_A_PMC3", 0x4c4, -1)
    idc.AddConstEx(id, "IA32_A_PMC4", 0x4c5, -1)
    idc.AddConstEx(id, "IA32_A_PMC5", 0x4c6, -1)
    idc.AddConstEx(id, "IA32_A_PMC6", 0x4c7, -1)
    idc.AddConstEx(id, "IA32_A_PMC7", 0x4c8, -1)
    idc.AddConstEx(id, "IA32_MCG_EXT_CTL", 0x4d0, -1)
    idc.AddConstEx(id, "IA32_SGX_SVN_STATUS", 0x500, -1)
    idc.AddConstEx(id, "IA32_RTIT_OUTPUT_BASE", 0x560, -1)
    idc.AddConstEx(id, "IA32_RTIT_OUTPUT_MASK_PTRS", 0x561, -1)
    idc.AddConstEx(id, "IA32_RTIT_CTL", 0x570, -1)
    idc.AddConstEx(id, "IA32_RTIT_STATUS", 0x571, -1)
    idc.AddConstEx(id, "IA32_RTIT_CR3_MATCH", 0x572, -1)
    idc.AddConstEx(id, "IA32_RTIT_ADDR0_A", 0x580, -1)
    idc.AddConstEx(id, "IA32_RTIT_ADDR1_A", 0x582, -1)
    idc.AddConstEx(id, "IA32_RTIT_ADDR2_A", 0x584, -1)
    idc.AddConstEx(id, "IA32_RTIT_ADDR3_A", 0x586, -1)
    idc.AddConstEx(id, "IA32_RTIT_ADDR0_B", 0x581, -1)
    idc.AddConstEx(id, "IA32_RTIT_ADDR1_B", 0x583, -1)
    idc.AddConstEx(id, "IA32_RTIT_ADDR2_B", 0x585, -1)
    idc.AddConstEx(id, "IA32_RTIT_ADDR3_B", 0x587, -1)
    idc.AddConstEx(id, "IA32_DS_AREA", 0x600, -1)
    idc.AddConstEx(id, "IA32_TSC_DEADLINE", 0x6e0, -1)
    idc.AddConstEx(id, "IA32_PM_ENABLE", 0x770, -1)
    idc.AddConstEx(id, "IA32_HWP_CAPABILITIES", 0x771, -1)
    idc.AddConstEx(id, "IA32_HWP_REQUEST_PKG", 0x772, -1)
    idc.AddConstEx(id, "IA32_HWP_INTERRUPT", 0x773, -1)
    idc.AddConstEx(id, "IA32_HWP_REQUEST", 0x774, -1)
    idc.AddConstEx(id, "IA32_HWP_STATUS", 0x777, -1)
    idc.AddConstEx(id, "IA32_X2APIC_APICID", 0x802, -1)
    idc.AddConstEx(id, "IA32_X2APIC_VERSION", 0x803, -1)
    idc.AddConstEx(id, "IA32_X2APIC_TPR", 0x808, -1)
    idc.AddConstEx(id, "IA32_X2APIC_PPR", 0x80a, -1)
    idc.AddConstEx(id, "IA32_X2APIC_EOI", 0x80b, -1)
    idc.AddConstEx(id, "IA32_X2APIC_LDR", 0x80d, -1)
    idc.AddConstEx(id, "IA32_X2APIC_SIVR", 0x80f, -1)
    idc.AddConstEx(id, "IA32_X2APIC_ISR0", 0x810, -1)
    idc.AddConstEx(id, "IA32_X2APIC_ISR1", 0x811, -1)
    idc.AddConstEx(id, "IA32_X2APIC_ISR2", 0x812, -1)
    idc.AddConstEx(id, "IA32_X2APIC_ISR3", 0x813, -1)
    idc.AddConstEx(id, "IA32_X2APIC_ISR4", 0x814, -1)
    idc.AddConstEx(id, "IA32_X2APIC_ISR5", 0x815, -1)
    idc.AddConstEx(id, "IA32_X2APIC_ISR6", 0x816, -1)
    idc.AddConstEx(id, "IA32_X2APIC_ISR7", 0x817, -1)
    idc.AddConstEx(id, "IA32_X2APIC_TMR0", 0x818, -1)
    idc.AddConstEx(id, "IA32_X2APIC_TMR1", 0x819, -1)
    idc.AddConstEx(id, "IA32_X2APIC_TMR2", 0x81a, -1)
    idc.AddConstEx(id, "IA32_X2APIC_TMR3", 0x81b, -1)
    idc.AddConstEx(id, "IA32_X2APIC_TMR4", 0x81c, -1)
    idc.AddConstEx(id, "IA32_X2APIC_TMR5", 0x81d, -1)
    idc.AddConstEx(id, "IA32_X2APIC_TMR6", 0x81e, -1)
    idc.AddConstEx(id, "IA32_X2APIC_TMR7", 0x81f, -1)
    idc.AddConstEx(id, "IA32_X2APIC_IRR0", 0x820, -1)
    idc.AddConstEx(id, "IA32_X2APIC_IRR1", 0x821, -1)
    idc.AddConstEx(id, "IA32_X2APIC_IRR2", 0x822, -1)
    idc.AddConstEx(id, "IA32_X2APIC_IRR3", 0x823, -1)
    idc.AddConstEx(id, "IA32_X2APIC_IRR4", 0x824, -1)
    idc.AddConstEx(id, "IA32_X2APIC_IRR5", 0x825, -1)
    idc.AddConstEx(id, "IA32_X2APIC_IRR6", 0x826, -1)
    idc.AddConstEx(id, "IA32_X2APIC_IRR7", 0x827, -1)
    idc.AddConstEx(id, "IA32_X2APIC_ESR", 0x828, -1)
    idc.AddConstEx(id, "IA32_X2APIC_LVT_CMCI", 0x82f, -1)
    idc.AddConstEx(id, "IA32_X2APIC_ICR", 0x830, -1)
    idc.AddConstEx(id, "IA32_X2APIC_LVT_TIMER", 0x832, -1)
    idc.AddConstEx(id, "IA32_X2APIC_LVT_THERMAL", 0x833, -1)
    idc.AddConstEx(id, "IA32_X2APIC_LVT_PMI", 0x834, -1)
    idc.AddConstEx(id, "IA32_X2APIC_LVT_LINT0", 0x835, -1)
    idc.AddConstEx(id, "IA32_X2APIC_LVT_LINT1", 0x836, -1)
    idc.AddConstEx(id, "IA32_X2APIC_LVT_ERROR", 0x837, -1)
    idc.AddConstEx(id, "IA32_X2APIC_INIT_COUNT", 0x838, -1)
    idc.AddConstEx(id, "IA32_X2APIC_CUR_COUNT", 0x839, -1)
    idc.AddConstEx(id, "IA32_X2APIC_DIV_CONF", 0x83e, -1)
    idc.AddConstEx(id, "IA32_X2APIC_SELF_IPI", 0x83f, -1)
    idc.AddConstEx(id, "IA32_DEBUG_INTERFACE", 0xc80, -1)
    idc.AddConstEx(id, "IA32_L2_QOS_CFG", 0xc82, -1)
    idc.AddConstEx(id, "IA32_QM_CTR", 0xc8e, -1)
    idc.AddConstEx(id, "IA32_BNDCFGS", 0xd90, -1)
    idc.AddConstEx(id, "IA32_XSS", 0xda0, -1)
    idc.AddConstEx(id, "IA32_PKG_HDC_CTL", 0xdb0, -1)
    idc.AddConstEx(id, "IA32_PM_CTL1", 0xdb1, -1)
    idc.AddConstEx(id, "IA32_THREAD_STALL", 0xdb2, -1)
    idc.AddConstEx(id, "IA32_EFER", 0xc0000080, -1)
    idc.AddConstEx(id, "IA32_STAR", 0xc0000081, -1)
    idc.AddConstEx(id, "IA32_LSTAR", 0xc0000082, -1)
    idc.AddConstEx(id, "IA32_CSTAR", 0xc0000083, -1)
    idc.AddConstEx(id, "IA32_FMASK", 0xc0000084, -1)
    idc.AddConstEx(id, "IA32_FS_BASE", 0xc0000100, -1)
    idc.AddConstEx(id, "IA32_GS_BASE", 0xc0000101, -1)
    idc.AddConstEx(id, "IA32_KERNEL_GS_BASE", 0xc0000102, -1)
    idc.AddConstEx(id, "IA32_TSC_AUX", 0xc0000103, -1)
    # ------------------------------------------------------------------------------------- #
    # VMCS 
    # ------------------------------------------------------------------------------------- #
    id = idc.AddEnum(0, "IA32_VMCS_LIST_ENUM", idaapi.hexflag())
    idc.AddConstEx(id, "VMCS_CTRL_VPID", 0x0, -1)
    idc.AddConstEx(id, "VMCS_CTRL_POSTED_INTR_NOTIFY_VECTOR", 0x2, -1)
    idc.AddConstEx(id, "VMCS_CTRL_EPTP_INDEX", 0x4, -1)
    idc.AddConstEx(id, "VMCS_GUEST_ES_SEL", 0x800, -1)
    idc.AddConstEx(id, "VMCS_GUEST_CS_SEL", 0x802, -1)
    idc.AddConstEx(id, "VMCS_GUEST_SS_SEL", 0x804, -1)
    idc.AddConstEx(id, "VMCS_GUEST_DS_SEL", 0x806, -1)
    idc.AddConstEx(id, "VMCS_GUEST_FS_SEL", 0x808, -1)
    idc.AddConstEx(id, "VMCS_GUEST_GS_SEL", 0x80a, -1)
    idc.AddConstEx(id, "VMCS_GUEST_LDTR_SEL", 0x80c, -1)
    idc.AddConstEx(id, "VMCS_GUEST_TR_SEL", 0x80e, -1)
    idc.AddConstEx(id, "VMCS_GUEST_INTR_STATUS", 0x810, -1)
    idc.AddConstEx(id, "VMCS_GUEST_PML_INDEX", 0x812, -1)
    idc.AddConstEx(id, "VMCS_HOST_ES_SEL", 0xc00, -1)
    idc.AddConstEx(id, "VMCS_HOST_CS_SEL", 0xc02, -1)
    idc.AddConstEx(id, "VMCS_HOST_SS_SEL", 0xc04, -1)
    idc.AddConstEx(id, "VMCS_HOST_DS_SEL", 0xc06, -1)
    idc.AddConstEx(id, "VMCS_HOST_FS_SEL", 0xc08, -1)
    idc.AddConstEx(id, "VMCS_HOST_GS_SEL", 0xc0a, -1)
    idc.AddConstEx(id, "VMCS_HOST_TR_SEL", 0xc0c, -1)
    idc.AddConstEx(id, "VMCS_CTRL_IO_BITMAP_A", 0x2000, -1)
    idc.AddConstEx(id, "VMCS_CTRL_IO_BITMAP_B", 0x2002, -1)
    idc.AddConstEx(id, "VMCS_CTRL_MSR_BITMAP", 0x2004, -1)
    idc.AddConstEx(id, "VMCS_CTRL_VMEXIT_MSR_STORE", 0x2006, -1)
    idc.AddConstEx(id, "VMCS_CTRL_VMEXIT_MSR_LOAD", 0x2008, -1)
    idc.AddConstEx(id, "VMCS_CTRL_VMENTRY_MSR_LOAD", 0x200a, -1)
    idc.AddConstEx(id, "VMCS_CTRL_EXEC_VMCS_PTR", 0x200c, -1)
    idc.AddConstEx(id, "VMCS_CTRL_PML_ADDR", 0x200e, -1)
    idc.AddConstEx(id, "VMCS_CTRL_TSC_OFFSET", 0x2010, -1)
    idc.AddConstEx(id, "VMCS_CTRL_VAPIC_PAGEADDR", 0x2012, -1)
    idc.AddConstEx(id, "VMCS_CTRL_APIC_ACCESSADDR", 0x2014, -1)
    idc.AddConstEx(id, "VMCS_CTRL_POSTED_INTR_DESC", 0x2016, -1)
    idc.AddConstEx(id, "VMCS_CTRL_VMFUNC_CTRLS", 0x2018, -1)
    idc.AddConstEx(id, "VMCS_CTRL_EPTP", 0x201a, -1)
    idc.AddConstEx(id, "VMCS_CTRL_EOI_BITMAP_0", 0x201c, -1)
    idc.AddConstEx(id, "VMCS_CTRL_EOI_BITMAP_1", 0x201e, -1)
    idc.AddConstEx(id, "VMCS_CTRL_EOI_BITMAP_2", 0x2020, -1)
    idc.AddConstEx(id, "VMCS_CTRL_EOI_BITMAP_3", 0x2022, -1)
    idc.AddConstEx(id, "VMCS_CTRL_EPTP_LIST", 0x2024, -1)
    idc.AddConstEx(id, "VMCS_CTRL_VMREAD_BITMAP", 0x2026, -1)
    idc.AddConstEx(id, "VMCS_CTRL_VMWRITE_BITMAP", 0x2028, -1)
    idc.AddConstEx(id, "VMCS_CTRL_VIRTXCPT_INFO_ADDR", 0x202a, -1)
    idc.AddConstEx(id, "VMCS_CTRL_XSS_EXITING_BITMAP", 0x202c, -1)
    idc.AddConstEx(id, "VMCS_CTRL_ENCLS_EXITING_BITMAP", 0x202e, -1)
    idc.AddConstEx(id, "VMCS_CTRL_TSC_MULTIPLIER", 0x2032, -1)
    idc.AddConstEx(id, "VMCS_GUEST_PHYS_ADDR", 0x2400, -1)
    idc.AddConstEx(id, "VMCS_GUEST_VMCS_LINK_PTR", 0x2800, -1)
    idc.AddConstEx(id, "VMCS_GUEST_DEBUGCTL", 0x2802, -1)
    idc.AddConstEx(id, "VMCS_GUEST_PAT", 0x2804, -1)
    idc.AddConstEx(id, "VMCS_GUEST_EFER", 0x2806, -1)
    idc.AddConstEx(id, "VMCS_GUEST_PERF_GLOBAL_CTRL", 0x2808, -1)
    idc.AddConstEx(id, "VMCS_GUEST_PDPTE0", 0x280a, -1)
    idc.AddConstEx(id, "VMCS_GUEST_PDPTE1", 0x280c, -1)
    idc.AddConstEx(id, "VMCS_GUEST_PDPTE2", 0x280e, -1)
    idc.AddConstEx(id, "VMCS_GUEST_PDPTE3", 0x2810, -1)
    idc.AddConstEx(id, "VMCS_HOST_PAT", 0x2c00, -1)
    idc.AddConstEx(id, "VMCS_HOST_EFER", 0x2c02, -1)
    idc.AddConstEx(id, "VMCS_HOST_PERF_GLOBAL_CTRL", 0x2c04, -1)
    idc.AddConstEx(id, "VMCS_CTRL_PIN_EXEC", 0x4000, -1)
    idc.AddConstEx(id, "VMCS_CTRL_PROC_EXEC", 0x4002, -1)
    idc.AddConstEx(id, "VMCS_CTRL_EXCEPTION_BITMAP", 0x4004, -1)
    idc.AddConstEx(id, "VMCS_CTRL_PAGEFAULT_ERROR_MASK", 0x4006, -1)
    idc.AddConstEx(id, "VMCS_CTRL_PAGEFAULT_ERROR_MATCH", 0x4008, -1)
    idc.AddConstEx(id, "VMCS_CTRL_CR3_TARGET_COUNT", 0x400a, -1)
    idc.AddConstEx(id, "VMCS_CTRL_EXIT", 0x400c, -1)
    idc.AddConstEx(id, "VMCS_CTRL_EXIT_MSR_STORE_COUNT", 0x400e, -1)
    idc.AddConstEx(id, "VMCS_CTRL_EXIT_MSR_LOAD_COUNT", 0x4010, -1)
    idc.AddConstEx(id, "VMCS_CTRL_ENTRY", 0x4012, -1)
    idc.AddConstEx(id, "VMCS_CTRL_ENTRY_MSR_LOAD_COUNT", 0x4014, -1)
    idc.AddConstEx(id, "VMCS_CTRL_ENTRY_INTERRUPTION_INFO", 0x4016, -1)
    idc.AddConstEx(id, "VMCS_CTRL_ENTRY_EXCEPTION_ERRCODE", 0x4018, -1)
    idc.AddConstEx(id, "VMCS_CTRL_ENTRY_INSTR_LENGTH", 0x401a, -1)
    idc.AddConstEx(id, "VMCS_CTRL_TPR_THRESHOLD", 0x401c, -1)
    idc.AddConstEx(id, "VMCS_CTRL_PROC_EXEC2", 0x401e, -1)
    idc.AddConstEx(id, "VMCS_CTRL_PLE_GAP", 0x4020, -1)
    idc.AddConstEx(id, "VMCS_CTRL_PLE_WINDOW", 0x4022, -1)
    idc.AddConstEx(id, "VMCS_VM_INSTR_ERROR", 0x4400, -1)
    idc.AddConstEx(id, "VMCS_EXIT_REASON", 0x4402, -1)
    idc.AddConstEx(id, "VMCS_EXIT_INTERRUPTION_INFO", 0x4404, -1)
    idc.AddConstEx(id, "VMCS_EXIT_INTERRUPTION_ERROR_CODE", 0x4406, -1)
    idc.AddConstEx(id, "VMCS_IDT_VECTORING_INFO", 0x4408, -1)
    idc.AddConstEx(id, "VMCS_IDT_VECTORING_ERROR_CODE", 0x440a, -1)
    idc.AddConstEx(id, "VMCS_EXIT_INSTR_LENGTH", 0x440c, -1)
    idc.AddConstEx(id, "VMCS_EXIT_INSTR_INFO", 0x440e, -1)
    idc.AddConstEx(id, "VMCS_GUEST_ES_LIMIT", 0x4800, -1)
    idc.AddConstEx(id, "VMCS_GUEST_CS_LIMIT", 0x4802, -1)
    idc.AddConstEx(id, "VMCS_GUEST_SS_LIMIT", 0x4804, -1)
    idc.AddConstEx(id, "VMCS_GUEST_DS_LIMIT", 0x4806, -1)
    idc.AddConstEx(id, "VMCS_GUEST_FS_LIMIT", 0x4808, -1)
    idc.AddConstEx(id, "VMCS_GUEST_GS_LIMIT", 0x480a, -1)
    idc.AddConstEx(id, "VMCS_GUEST_LDTR_LIMIT", 0x480c, -1)
    idc.AddConstEx(id, "VMCS_GUEST_TR_LIMIT", 0x480e, -1)
    idc.AddConstEx(id, "VMCS_GUEST_GDTR_LIMIT", 0x4810, -1)
    idc.AddConstEx(id, "VMCS_GUEST_IDTR_LIMIT", 0x4812, -1)
    idc.AddConstEx(id, "VMCS_GUEST_ES_ACCESS_RIGHTS", 0x4814, -1)
    idc.AddConstEx(id, "VMCS_GUEST_CS_ACCESS_RIGHTS", 0x4816, -1)
    idc.AddConstEx(id, "VMCS_GUEST_SS_ACCESS_RIGHTS", 0x4818, -1)
    idc.AddConstEx(id, "VMCS_GUEST_DS_ACCESS_RIGHTS", 0x481a, -1)
    idc.AddConstEx(id, "VMCS_GUEST_FS_ACCESS_RIGHTS", 0x481c, -1)
    idc.AddConstEx(id, "VMCS_GUEST_GS_ACCESS_RIGHTS", 0x481e, -1)
    idc.AddConstEx(id, "VMCS_GUEST_LDTR_ACCESS_RIGHTS", 0x4820, -1)
    idc.AddConstEx(id, "VMCS_GUEST_TR_ACCESS_RIGHTS", 0x4822, -1)
    idc.AddConstEx(id, "VMCS_GUEST_INTERRUPTIBILITY_STATE", 0x4824, -1)
    idc.AddConstEx(id, "VMCS_GUEST_ACTIVITY_STATE", 0x4826, -1)
    idc.AddConstEx(id, "VMCS_GUEST_SMBASE", 0x4828, -1)
    idc.AddConstEx(id, "VMCS_GUEST_SYSENTER_CS", 0x482a, -1)
    idc.AddConstEx(id, "VMCS_GUEST_PREEMPT_TIMER_VALUE", 0x482e, -1)
    idc.AddConstEx(id, "VMCS_SYSENTER_CS", 0x4c00, -1)
    idc.AddConstEx(id, "VMCS_CTRL_CR0_MASK", 0x6000, -1)
    idc.AddConstEx(id, "VMCS_CTRL_CR4_MASK", 0x6002, -1)
    idc.AddConstEx(id, "VMCS_CTRL_CR0_READ_SHADOW", 0x6004, -1)
    idc.AddConstEx(id, "VMCS_CTRL_CR4_READ_SHADOW", 0x6006, -1)
    idc.AddConstEx(id, "VMCS_CTRL_CR3_TARGET_VAL0", 0x6008, -1)
    idc.AddConstEx(id, "VMCS_CTRL_CR3_TARGET_VAL1", 0x600a, -1)
    idc.AddConstEx(id, "VMCS_CTRL_CR3_TARGET_VAL2", 0x600c, -1)
    idc.AddConstEx(id, "VMCS_CTRL_CR3_TARGET_VAL3", 0x600e, -1)
    idc.AddConstEx(id, "VMCS_EXIT_QUALIFICATION", 0x6400, -1)
    idc.AddConstEx(id, "VMCS_IO_RCX", 0x6402, -1)
    idc.AddConstEx(id, "VMCS_IO_RSX", 0x6404, -1)
    idc.AddConstEx(id, "VMCS_IO_RDI", 0x6406, -1)
    idc.AddConstEx(id, "VMCS_IO_RIP", 0x6408, -1)
    idc.AddConstEx(id, "VMCS_EXIT_GUEST_LINEAR_ADDR", 0x640a, -1)
    idc.AddConstEx(id, "VMCS_GUEST_CR0", 0x6800, -1)
    idc.AddConstEx(id, "VMCS_GUEST_CR3", 0x6802, -1)
    idc.AddConstEx(id, "VMCS_GUEST_CR4", 0x6804, -1)
    idc.AddConstEx(id, "VMCS_GUEST_ES_BASE", 0x6806, -1)
    idc.AddConstEx(id, "VMCS_GUEST_CS_BASE", 0x6808, -1)
    idc.AddConstEx(id, "VMCS_GUEST_SS_BASE", 0x680a, -1)
    idc.AddConstEx(id, "VMCS_GUEST_DS_BASE", 0x680c, -1)
    idc.AddConstEx(id, "VMCS_GUEST_FS_BASE", 0x680e, -1)
    idc.AddConstEx(id, "VMCS_GUEST_GS_BASE", 0x6810, -1)
    idc.AddConstEx(id, "VMCS_GUEST_LDTR_BASE", 0x6812, -1)
    idc.AddConstEx(id, "VMCS_GUEST_TR_BASE", 0x6814, -1)
    idc.AddConstEx(id, "VMCS_GUEST_GDTR_BASE", 0x6816, -1)
    idc.AddConstEx(id, "VMCS_GUEST_IDTR_BASE", 0x6818, -1)
    idc.AddConstEx(id, "VMCS_GUEST_DR7", 0x681a, -1)
    idc.AddConstEx(id, "VMCS_GUEST_RSP", 0x681c, -1)
    idc.AddConstEx(id, "VMCS_GUEST_RIP", 0x681e, -1)
    idc.AddConstEx(id, "VMCS_GUEST_RFLAGS", 0x6820, -1)
    idc.AddConstEx(id, "VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS", 0x6822, -1)
    idc.AddConstEx(id, "VMCS_GUEST_SYSENTER_ESP", 0x6824, -1)
    idc.AddConstEx(id, "VMCS_GUEST_SYSENTER_EIP", 0x6826, -1)
    idc.AddConstEx(id, "VMCS_HOST_CR0", 0x6c00, -1)
    idc.AddConstEx(id, "VMCS_HOST_CR3", 0x6c02, -1)
    idc.AddConstEx(id, "VMCS_HOST_CR4", 0x6c04, -1)
    idc.AddConstEx(id, "VMCS_HOST_FS_BASE", 0x6c06, -1)
    idc.AddConstEx(id, "VMCS_HOST_GS_BASE", 0x6c08, -1)
    idc.AddConstEx(id, "VMCS_HOST_TR_BASE", 0x6c0a, -1)
    idc.AddConstEx(id, "VMCS_HOST_GDTR_BASE", 0x6c0c, -1)
    idc.AddConstEx(id, "VMCS_HOST_IDTR_BASE", 0x6c0e, -1)
    idc.AddConstEx(id, "VMCS_HOST_SYSENTER_ESP", 0x6c10, -1)
    idc.AddConstEx(id, "VMCS_HOST_SYSENTER_EIP", 0x6c12, -1)
    idc.AddConstEx(id, "VMCS_HOST_RSP", 0x6c14, -1)
    idc.AddConstEx(id, "VMCS_HOST_RIP", 0x6c16, -1)
    idc.AddConstEx(id, "VMCS_GUEST_PDPTR3_HIGH", 0x2811, -1)
    idc.AddConstEx(id, "VMCS_GUEST_BNDCFGS", 0x2812, -1)
    idc.AddConstEx(id, "VMCS_GUEST_BNDCFGS_HIGH", 0x2813, -1)
    idc.AddConstEx(id, "VMCS_GUEST_RTIT_CTL", 0x2814, -1)
    idc.AddConstEx(id, "VMCS_GUEST_RTIT_CTL_HIGH", 0x2815, -1)

# ------------------------------------------------------------------------------------- #
class KnowledgeDb():
    def __init__(self):
        self.ia32_vmcs_db = {
            0x00000000 : 'VMCS_CTRL_VPID',
            0x00000002 : 'VMCS_CTRL_POSTED_INTR_NOTIFY_VECTOR',
            0x00000004 : 'VMCS_CTRL_EPTP_INDEX',
            0x00000800 : 'VMCS_GUEST_ES_SEL',
            0x00000802 : 'VMCS_GUEST_CS_SEL',
            0x00000804 : 'VMCS_GUEST_SS_SEL',
            0x00000806 : 'VMCS_GUEST_DS_SEL',
            0x00000808 : 'VMCS_GUEST_FS_SEL',
            0x0000080A : 'VMCS_GUEST_GS_SEL',
            0x0000080C : 'VMCS_GUEST_LDTR_SEL',
            0x0000080E : 'VMCS_GUEST_TR_SEL',
            0x00000810 : 'VMCS_GUEST_INTR_STATUS',
            0x00000812 : 'VMCS_GUEST_PML_INDEX',
            0x00000C00 : 'VMCS_HOST_ES_SEL',
            0x00000C02 : 'VMCS_HOST_CS_SEL',
            0x00000C04 : 'VMCS_HOST_SS_SEL',
            0x00000C06 : 'VMCS_HOST_DS_SEL',
            0x00000C08 : 'VMCS_HOST_FS_SEL',
            0x00000C0A : 'VMCS_HOST_GS_SEL',
            0x00000C0C : 'VMCS_HOST_TR_SEL',
            0x00002000 : 'VMCS_CTRL_IO_BITMAP_A',
            0x00002002 : 'VMCS_CTRL_IO_BITMAP_B',
            0x00002004 : 'VMCS_CTRL_MSR_BITMAP',
            0x00002006 : 'VMCS_CTRL_VMEXIT_MSR_STORE',
            0x00002008 : 'VMCS_CTRL_VMEXIT_MSR_LOAD',
            0x0000200A : 'VMCS_CTRL_VMENTRY_MSR_LOAD',
            0x0000200C : 'VMCS_CTRL_EXEC_VMCS_PTR',
            0x0000200E : 'VMCS_CTRL_PML_ADDR',
            0x00002010 : 'VMCS_CTRL_TSC_OFFSET',
            0x00002012 : 'VMCS_CTRL_VAPIC_PAGEADDR',
            0x00002014 : 'VMCS_CTRL_APIC_ACCESSADDR',
            0x00002016 : 'VMCS_CTRL_POSTED_INTR_DESC',
            0x00002018 : 'VMCS_CTRL_VMFUNC_CTRLS',
            0x0000201A : 'VMCS_CTRL_EPTP',
            0x0000201C : 'VMCS_CTRL_EOI_BITMAP_0',
            0x0000201E : 'VMCS_CTRL_EOI_BITMAP_1',
            0x00002020 : 'VMCS_CTRL_EOI_BITMAP_2',
            0x00002022 : 'VMCS_CTRL_EOI_BITMAP_3',
            0x00002024 : 'VMCS_CTRL_EPTP_LIST',
            0x00002026 : 'VMCS_CTRL_VMREAD_BITMAP',
            0x00002028 : 'VMCS_CTRL_VMWRITE_BITMAP',
            0x0000202A : 'VMCS_CTRL_VIRTXCPT_INFO_ADDR',
            0x0000202C : 'VMCS_CTRL_XSS_EXITING_BITMAP',
            0x0000202E : 'VMCS_CTRL_ENCLS_EXITING_BITMAP',
            0x00002032 : 'VMCS_CTRL_TSC_MULTIPLIER',
            0x00002400 : 'VMCS_GUEST_PHYS_ADDR',
            0x00002800 : 'VMCS_GUEST_VMCS_LINK_PTR',
            0x00002802 : 'VMCS_GUEST_DEBUGCTL',
            0x00002804 : 'VMCS_GUEST_PAT',
            0x00002806 : 'VMCS_GUEST_EFER',
            0x00002808 : 'VMCS_GUEST_PERF_GLOBAL_CTRL',
            0x0000280A : 'VMCS_GUEST_PDPTE0',
            0x0000280C : 'VMCS_GUEST_PDPTE1',
            0x0000280E : 'VMCS_GUEST_PDPTE2',
            0x00002810 : 'VMCS_GUEST_PDPTE3',
            0x00002C00 : 'VMCS_HOST_PAT',
            0x00002C02 : 'VMCS_HOST_EFER',
            0x00002C04 : 'VMCS_HOST_PERF_GLOBAL_CTRL',
            0x00004000 : 'VMCS_CTRL_PIN_EXEC',
            0x00004002 : 'VMCS_CTRL_PROC_EXEC',
            0x00004004 : 'VMCS_CTRL_EXCEPTION_BITMAP',
            0x00004006 : 'VMCS_CTRL_PAGEFAULT_ERROR_MASK',
            0x00004008 : 'VMCS_CTRL_PAGEFAULT_ERROR_MATCH',
            0x0000400A : 'VMCS_CTRL_CR3_TARGET_COUNT',
            0x0000400C : 'VMCS_CTRL_EXIT',
            0x0000400E : 'VMCS_CTRL_EXIT_MSR_STORE_COUNT',
            0x00004010 : 'VMCS_CTRL_EXIT_MSR_LOAD_COUNT',
            0x00004012 : 'VMCS_CTRL_ENTRY',
            0x00004014 : 'VMCS_CTRL_ENTRY_MSR_LOAD_COUNT',
            0x00004016 : 'VMCS_CTRL_ENTRY_INTERRUPTION_INFO',
            0x00004018 : 'VMCS_CTRL_ENTRY_EXCEPTION_ERRCODE',
            0x0000401A : 'VMCS_CTRL_ENTRY_INSTR_LENGTH',
            0x0000401C : 'VMCS_CTRL_TPR_THRESHOLD',
            0x0000401E : 'VMCS_CTRL_PROC_EXEC2',
            0x00004020 : 'VMCS_CTRL_PLE_GAP',
            0x00004022 : 'VMCS_CTRL_PLE_WINDOW',
            0x00004400 : 'VMCS_VM_INSTR_ERROR',
            0x00004402 : 'VMCS_EXIT_REASON',
            0x00004404 : 'VMCS_EXIT_INTERRUPTION_INFO',
            0x00004406 : 'VMCS_EXIT_INTERRUPTION_ERROR_CODE',
            0x00004408 : 'VMCS_IDT_VECTORING_INFO',
            0x0000440A : 'VMCS_IDT_VECTORING_ERROR_CODE',
            0x0000440C : 'VMCS_EXIT_INSTR_LENGTH',
            0x0000440E : 'VMCS_EXIT_INSTR_INFO',
            0x00004800 : 'VMCS_GUEST_ES_LIMIT',
            0x00004802 : 'VMCS_GUEST_CS_LIMIT',
            0x00004804 : 'VMCS_GUEST_SS_LIMIT',
            0x00004806 : 'VMCS_GUEST_DS_LIMIT',
            0x00004808 : 'VMCS_GUEST_FS_LIMIT',
            0x0000480A : 'VMCS_GUEST_GS_LIMIT',
            0x0000480C : 'VMCS_GUEST_LDTR_LIMIT',
            0x0000480E : 'VMCS_GUEST_TR_LIMIT',
            0x00004810 : 'VMCS_GUEST_GDTR_LIMIT',
            0x00004812 : 'VMCS_GUEST_IDTR_LIMIT',
            0x00004814 : 'VMCS_GUEST_ES_ACCESS_RIGHTS',
            0x00004816 : 'VMCS_GUEST_CS_ACCESS_RIGHTS',
            0x00004818 : 'VMCS_GUEST_SS_ACCESS_RIGHTS',
            0x0000481A : 'VMCS_GUEST_DS_ACCESS_RIGHTS',
            0x0000481C : 'VMCS_GUEST_FS_ACCESS_RIGHTS',
            0x0000481E : 'VMCS_GUEST_GS_ACCESS_RIGHTS',
            0x00004820 : 'VMCS_GUEST_LDTR_ACCESS_RIGHTS',
            0x00004822 : 'VMCS_GUEST_TR_ACCESS_RIGHTS',
            0x00004824 : 'VMCS_GUEST_INTERRUPTIBILITY_STATE',
            0x00004826 : 'VMCS_GUEST_ACTIVITY_STATE',
            0x00004828 : 'VMCS_GUEST_SMBASE',
            0x0000482A : 'VMCS_GUEST_SYSENTER_CS',
            0x0000482E : 'VMCS_GUEST_PREEMPT_TIMER_VALUE',
            0x00004C00 : 'VMCS_SYSENTER_CS',
            0x00006000 : 'VMCS_CTRL_CR0_MASK',
            0x00006002 : 'VMCS_CTRL_CR4_MASK',
            0x00006004 : 'VMCS_CTRL_CR0_READ_SHADOW',
            0x00006006 : 'VMCS_CTRL_CR4_READ_SHADOW',
            0x00006008 : 'VMCS_CTRL_CR3_TARGET_VAL0',
            0x0000600A : 'VMCS_CTRL_CR3_TARGET_VAL1',
            0x0000600C : 'VMCS_CTRL_CR3_TARGET_VAL2',
            0x0000600E : 'VMCS_CTRL_CR3_TARGET_VAL3',
            0x00006400 : 'VMCS_EXIT_QUALIFICATION',
            0x00006402 : 'VMCS_IO_RCX',
            0x00006404 : 'VMCS_IO_RSX',
            0x00006406 : 'VMCS_IO_RDI',
            0x00006408 : 'VMCS_IO_RIP',
            0x0000640A : 'VMCS_EXIT_GUEST_LINEAR_ADDR',
            0x00006800 : 'VMCS_GUEST_CR0',
            0x00006802 : 'VMCS_GUEST_CR3',
            0x00006804 : 'VMCS_GUEST_CR4',
            0x00006806 : 'VMCS_GUEST_ES_BASE',
            0x00006808 : 'VMCS_GUEST_CS_BASE',
            0x0000680A : 'VMCS_GUEST_SS_BASE',
            0x0000680C : 'VMCS_GUEST_DS_BASE',
            0x0000680E : 'VMCS_GUEST_FS_BASE',
            0x00006810 : 'VMCS_GUEST_GS_BASE',
            0x00006812 : 'VMCS_GUEST_LDTR_BASE',
            0x00006814 : 'VMCS_GUEST_TR_BASE',
            0x00006816 : 'VMCS_GUEST_GDTR_BASE',
            0x00006818 : 'VMCS_GUEST_IDTR_BASE',
            0x0000681A : 'VMCS_GUEST_DR7',
            0x0000681C : 'VMCS_GUEST_RSP',
            0x0000681E : 'VMCS_GUEST_RIP',
            0x00006820 : 'VMCS_GUEST_RFLAGS',
            0x00006822 : 'VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS',
            0x00006824 : 'VMCS_GUEST_SYSENTER_ESP',
            0x00006826 : 'VMCS_GUEST_SYSENTER_EIP',
            0x00006C00 : 'VMCS_HOST_CR0',
            0x00006C02 : 'VMCS_HOST_CR3',
            0x00006C04 : 'VMCS_HOST_CR4',
            0x00006C06 : 'VMCS_HOST_FS_BASE',
            0x00006C08 : 'VMCS_HOST_GS_BASE',
            0x00006C0A : 'VMCS_HOST_TR_BASE',
            0x00006C0C : 'VMCS_HOST_GDTR_BASE',
            0x00006C0E : 'VMCS_HOST_IDTR_BASE',
            0x00006C10 : 'VMCS_HOST_SYSENTER_ESP',
            0x00006C12 : 'VMCS_HOST_SYSENTER_EIP',
            0x00006C14 : 'VMCS_HOST_RSP',
            0x00006C16 : 'VMCS_HOST_RIP',

                    # new https://lore.kernel.org/patchwork/patch/1002950/.
            0x00002811 : 'VMCS_GUEST_PDPTR3_HIGH',
            0x00002812 : 'VMCS_GUEST_BNDCFGS',
            0x00002813 : 'VMCS_GUEST_BNDCFGS_HIGH',
            0x00002814 : 'VMCS_GUEST_RTIT_CTL',
            0x00002815 : 'VMCS_GUEST_RTIT_CTL_HIGH'
            }

        self.ia32_msr_db = {

            #
            # Hyper-V MSRs
            #
            0x40000000 : 'HV_X64_MSR_GUEST_OS_ID',
            0x40000001 : 'HV_X64_MSR_HYPERCALL',
            0x40000002 : 'HV_X64_MSR_VP_INDEX',
            0x40000003 : 'HV_X64_MSR_RESET',
            0x40000010 : 'HV_X64_MSR_VP_RUNTIME',
            0x40000020 : 'HV_X64_MSR_TIME_REF_COUNT',
            0x40000021 : 'HV_X64_MSR_REFERENCE_TSC',
            0x40000022 : 'HV_X64_MSR_TSC_FREQUENCY',
            0x40000023 : 'HV_X64_MSR_APIC_FREQUENCY',
            0x40000070 : 'HV_X64_MSR_EOI',
            0x40000071 : 'HV_X64_MSR_ICR',
            0x40000072 : 'HV_X64_MSR_TPR',
            0x40000073 : 'HV_X64_MSR_VP_ASSIST_PAGE',
            0x40000080 : 'HV_X64_MSR_SCONTROL',
            0x40000081 : 'HV_X64_MSR_SVERSION',
            0x40000082 : 'HV_X64_MSR_SIEFP',
            0x40000083 : 'HV_X64_MSR_SIMP',
            0x40000084 : 'HV_X64_MSR_EOM',
            0x40000090 : 'HV_X64_MSR_SINT0',
            0x40000091 : 'HV_X64_MSR_SINT1',
            0x40000092 : 'HV_X64_MSR_SINT2',
            0x40000093 : 'HV_X64_MSR_SINT3',
            0x40000094 : 'HV_X64_MSR_SINT4',
            0x40000095 : 'HV_X64_MSR_SINT5',
            0x40000096 : 'HV_X64_MSR_SINT6',
            0x40000097 : 'HV_X64_MSR_SINT7',
            0x40000098 : 'HV_X64_MSR_SINT8',
            0x40000099 : 'HV_X64_MSR_SINT9',
            0x4000009A : 'HV_X64_MSR_SINT10',
            0x4000009B : 'HV_X64_MSR_SINT11',
            0x4000009C : 'HV_X64_MSR_SINT12',
            0x4000009D : 'HV_X64_MSR_SINT13',
            0x4000009E : 'HV_X64_MSR_SINT14',
            0x4000009F : 'HV_X64_MSR_SINT15',
            0x400000B0 : 'HV_X64_MSR_STIMER0_CONFIG',
            0x400000B1 : 'HV_X64_MSR_STIMER0_COUNT',
            0x400000B2 : 'HV_X64_MSR_STIMER1_CONFIG',
            0x400000B3 : 'HV_X64_MSR_STIMER1_COUNT',
            0x400000B4 : 'HV_X64_MSR_STIMER2_CONFIG',
            0x400000B5 : 'HV_X64_MSR_STIMER2_COUNT',
            0x400000B6 : 'HV_X64_MSR_STIMER3_CONFIG',
            0x400000B7 : 'HV_X64_MSR_STIMER3_COUNT',
            0x400000C1 : 'HV_X64_MSR_POWER_STATE_TRIGGER_C1',
            0x400000C2 : 'HV_X64_MSR_POWER_STATE_TRIGGER_C2',
            0x400000C3 : 'HV_X64_MSR_POWER_STATE_TRIGGER_C3',
            0x400000D1 : 'HV_X64_MSR_POWER_STATE_CONFIG_C1',
            0x400000D2 : 'HV_X64_MSR_POWER_STATE_CONFIG_C2',
            0x400000D3 : 'HV_X64_MSR_POWER_STATE_CONFIG_C3',
            0x400000E0 : 'HV_X64_MSR_STATS_PARTITION_RETAIL_PAGE',
            0x400000E1 : 'HV_X64_MSR_STATS_PARTITION_INTERNAL_PAGE',
            0x400000E2 : 'HV_X64_MSR_STATS_VP_RETAIL_PAGE',
            0x400000E3 : 'HV_X64_MSR_STATS_VP_INTERNAL_PAGE',
            0x400000F0 : 'HV_X64_MSR_GUEST_IDLE',
            0x400000F1 : 'HV_X64_MSR_SYNTH_DEBUG_CONTROL',
            0x400000F2 : 'HV_X64_MSR_SYNTH_DEBUG_STATUS',
            0x400000F3 : 'HV_X64_MSR_SYNTH_DEBUG_SEND_BUFFER',
            0x400000F4 : 'HV_X64_MSR_SYNTH_DEBUG_RECEIVE_BUFFER',
            0x400000F5 : 'HV_X64_MSR_SYNTH_DEBUG_PENDING_BUFFER',
            0x40000100 : 'HV_X64_MSR_CRASH_P0',
            0x40000101 : 'HV_X64_MSR_CRASH_P1',
            0x40000102 : 'HV_X64_MSR_CRASH_P2',
            0x40000103 : 'HV_X64_MSR_CRASH_P3',
            0x40000104 : 'HV_X64_MSR_CRASH_P4',
            0x40000105 : 'HV_X64_MSR_CRASH_CTL',

            0x40000106 : 'HV_X64_MSR_REENLIGHTENMENT_CONTROL',
            0x40000107 : 'HV_X64_MSR_TSC_EMULATION_CONTROL',
            0x40000108 : 'HV_X64_MSR_TSC_EMULATION_STATUS',


            #
            # XEON MSRs
            #
            0x0000004E : 'MSR_XEON_D_PPIN_CTL',
            0x0000004F : 'MSR_XEON_D_PPIN',
            0x000000CE : 'MSR_XEON_D_PLATFORM_INFO',
            0x000000E2 : 'MSR_XEON_D_PKG_CST_CONFIG_CONTROL',
            0x00000179 : 'MSR_XEON_D_IA32_MCG_CAP',
            0x0000017D : 'MSR_XEON_D_SMM_MCA_CAP',
            0x000001A2 : 'MSR_XEON_D_TEMPERATURE_TARGET',
            0x000001AD : 'MSR_XEON_D_TURBO_RATIO_LIMIT',
            0x000001AE : 'MSR_XEON_D_TURBO_RATIO_LIMIT1',
            0x00000606 : 'MSR_XEON_D_RAPL_POWER_UNIT',
            0x00000618 : 'MSR_XEON_D_DRAM_POWER_LIMIT',
            0x00000619 : 'MSR_XEON_D_DRAM_ENERGY_STATUS',
            0x0000061B : 'MSR_XEON_D_DRAM_PERF_STATUS',
            0x0000061C : 'MSR_XEON_D_DRAM_POWER_INFO',
            0x00000620 : 'MSR_XEON_D_MSRUNCORE_RATIO_LIMIT',
            0x00000639 : 'MSR_XEON_D_PP0_ENERGY_STATUS',
            0x00000690 : 'MSR_XEON_D_CORE_PERF_LIMIT_REASONS',
            0x00000C8D : 'MSR_XEON_D_IA32_QM_EVTSEL',
            0x00000C8F : 'MSR_XEON_D_IA32_PQR_ASSOC',
            0x000001AC : 'MSR_XEON_D_TURBO_RATIO_LIMIT3',
            0x00000C81 : 'MSR_XEON_D_IA32_L3_QOS_CFG',
            0x00000C90 : 'MSR_XEON_D_IA32_L3_QOS_MASK_0',
            0x00000C91 : 'MSR_XEON_D_IA32_L3_QOS_MASK_1',
            0x00000C92 : 'MSR_XEON_D_IA32_L3_QOS_MASK_2',
            0x00000C93 : 'MSR_XEON_D_IA32_L3_QOS_MASK_3',
            0x00000C94 : 'MSR_XEON_D_IA32_L3_QOS_MASK_4',
            0x00000C95 : 'MSR_XEON_D_IA32_L3_QOS_MASK_5',
            0x00000C96 : 'MSR_XEON_D_IA32_L3_QOS_MASK_6',
            0x00000C97 : 'MSR_XEON_D_IA32_L3_QOS_MASK_7',
            0x00000C98 : 'MSR_XEON_D_IA32_L3_QOS_MASK_8',
            0x00000C99 : 'MSR_XEON_D_IA32_L3_QOS_MASK_9',
            0x00000C9A : 'MSR_XEON_D_IA32_L3_QOS_MASK_10',
            0x00000C9B : 'MSR_XEON_D_IA32_L3_QOS_MASK_11',
            0x00000C9C : 'MSR_XEON_D_IA32_L3_QOS_MASK_12',
            0x00000C9D : 'MSR_XEON_D_IA32_L3_QOS_MASK_13',
            0x00000C9E : 'MSR_XEON_D_IA32_L3_QOS_MASK_14',
            0x00000C9F : 'MSR_XEON_D_IA32_L3_QOS_MASK_15',



            # 
            # QQQQQQQQQQ
            #

            0x00000048 : 'MSR_SPEC_CTRL',
            0x00000049 : 'MSR_PRED_CMD',

            0x000001C8 : 'MSR_LBR_SELECT',
            0x000001C9 : 'MSR_LBR_TOS',
            0x00000680 : 'MSR_LBR_NHM_FROM',
            0x000006C0 : 'MSR_LBR_NHM_TO',
            0x00000040 : 'MSR_LBR_CORE_FROM',
            0x00000060 : 'MSR_LBR_CORE_TO',


            0x000001DB : 'MSR_IA32_LASTBRANCHFROMIP',
            0x000001DC : 'MSR_IA32_LASTBRANCHTOIP',
            0x000001DD : 'MSR_IA32_LASTINTFROMIP',
            0x000001DE : 'MSR_IA32_LASTINTTOIP',

            # https://github.com/collectd/collectd/blob/master/src/msr-index.h
            #
            # C-state Residency Counters
            #
            0x000003F8 : 'MSR_PKG_C3_RESIDENCY',
            0x000003F9 : 'MSR_PKG_C6_RESIDENCY',
            0x000003FA : 'MSR_ATOM_PKG_C6_RESIDENCY',
            0x000003FA : 'MSR_PKG_C7_RESIDENCY',
            0x000003FC : 'MSR_CORE_C3_RESIDENCY',
            0x000003FD : 'MSR_CORE_C6_RESIDENCY',
            0x000003FE : 'MSR_CORE_C7_RESIDENCY',
            0x000003FF : 'MSR_KNL_CORE_C6_RESIDENCY',
            0x0000060D : 'MSR_PKG_C2_RESIDENCY',
            0x00000630 : 'MSR_PKG_C8_RESIDENCY',
            0x00000631 : 'MSR_PKG_C9_RESIDENCY',
            0x00000632 : 'MSR_PKG_C10_RESIDENCY',


            # https://sites.uclouvain.be/SystInfo/usr/include/asm/msr-index.h.html

            #
            # Centaur-Hauls/IDT defined MSRs.
            #
            0x00000107 : 'MSR_IDT_FCR1',
            0x00000108 : 'MSR_IDT_FCR2',
            0x00000109 : 'MSR_IDT_FCR3',
            0x0000010A : 'MSR_IDT_FCR4',
            0x00000110 : 'MSR_IDT_MCR0',
            0x00000111 : 'MSR_IDT_MCR1',
            0x00000112 : 'MSR_IDT_MCR2',
            0x00000113 : 'MSR_IDT_MCR3',
            0x00000114 : 'MSR_IDT_MCR4',
            0x00000115 : 'MSR_IDT_MCR5',
            0x00000116 : 'MSR_IDT_MCR6',
            0x00000117 : 'MSR_IDT_MCR7',
            0x00000120 : 'MSR_IDT_MCR_CTRL',


            0x000000CD : 'MSR_FSB_FREQ',
            0x00000119 : 'MSR_IA32_BBL_CR_CTL',

            # 
            # QQQQQQQQQQ
            #

            # AMD-V MSRs
            0xC0010114 : 'MSR_VM_CR',
            0xC0010115 : 'MSR_VM_IGNNE',
            0xC0010117 : 'MSR_VM_HSAVE_PA',



            ###########################################################
            # start https://github.com/wbenny/ia32-doc

            # @defgroup intel_manual \
            #           Intel Manual
            # BEGIN
            # @defgroup model_specific_registers \
            #           Model Specific Registers
            # BEGIN
            # @defgroup ia32_p5_mc \
            #           IA32_P5_MC_(x)
            # BEGIN
            0x00000000 : 'IA32_P5_MC_ADDR',
            0x00000001 : 'IA32_P5_MC_TYPE',
            # END

            0x00000006 : 'IA32_MONITOR_FILTER_SIZE',
            0x00000010 : 'IA32_TIME_STAMP_COUNTER',
            0x00000017 : 'IA32_PLATFORM_ID',
            0x0000001B : 'IA32_APIC_BASE',
            0x0000003A : 'IA32_FEATURE_CONTROL',
            0x0000003B : 'IA32_TSC_ADJUST',
            0x00000079 : 'IA32_BIOS_UPDT_TRIG',
            0x0000008B : 'IA32_BIOS_SIGN_ID',
            # @defgroup ia32_sgxlepubkeyhash \
            #           IA32_SGXLEPUBKEYHASH[(64*n+63):(64*n)]
            # BEGIN
            0x0000008C : 'IA32_SGXLEPUBKEYHASH0',
            0x0000008D : 'IA32_SGXLEPUBKEYHASH1',
            0x0000008E : 'IA32_SGXLEPUBKEYHASH2',
            0x0000008F : 'IA32_SGXLEPUBKEYHASH3',
            # END

            0x0000009B : 'IA32_SMM_MONITOR_CTL',
            0x0000009E : 'IA32_SMBASE',
            # @defgroup ia32_pmc \
            #           IA32_PMC(n)
            # BEGIN
            0x000000C1 : 'IA32_PMC0',
            0x000000C2 : 'IA32_PMC1',
            0x000000C3 : 'IA32_PMC2',
            0x000000C4 : 'IA32_PMC3',
            0x000000C5 : 'IA32_PMC4',
            0x000000C6 : 'IA32_PMC5',
            0x000000C7 : 'IA32_PMC6',
            0x000000C8 : 'IA32_PMC7',
            # END

            0x000000E7 : 'IA32_MPERF',
            0x000000E8 : 'IA32_APERF',
            0x000000FE : 'IA32_MTRRCAP',
            0x00000174 : 'IA32_SYSENTER_CS',
            0x00000175 : 'IA32_SYSENTER_ESP',
            0x00000176 : 'IA32_SYSENTER_EIP',
            0x00000179 : 'IA32_MCG_CAP',
            0x0000017A : 'IA32_MCG_STATUS',
            0x0000017B : 'IA32_MCG_CTL',
            # @defgroup ia32_perfevtsel \
            #           IA32_PERFEVTSEL(n)
            # BEGIN
            0x00000186 : 'IA32_PERFEVTSEL0',
            0x00000187 : 'IA32_PERFEVTSEL1',
            0x00000188 : 'IA32_PERFEVTSEL2',
            0x00000189 : 'IA32_PERFEVTSEL3',
            # END

            0x00000198 : 'IA32_PERF_STATUS',
            0x00000199 : 'IA32_PERF_CTL',
            0x0000019A : 'IA32_CLOCK_MODULATION',
            0x0000019B : 'IA32_THERM_INTERRUPT',
            0x0000019C : 'IA32_THERM_STATUS',
            0x000001A0 : 'IA32_MISC_ENABLE',
            0x000001B0 : 'IA32_ENERGY_PERF_BIAS',
            0x000001B1 : 'IA32_PACKAGE_THERM_STATUS',
            0x000001B2 : 'IA32_PACKAGE_THERM_INTERRUPT',
            0x000001D9 : 'IA32_DEBUGCTL',
            0x000001F2 : 'IA32_SMRR_PHYSBASE',
            0x000001F3 : 'IA32_SMRR_PHYSMASK',
            0x000001F8 : 'IA32_PLATFORM_DCA_CAP',
            0x000001F9 : 'IA32_CPU_DCA_CAP',
            0x000001FA : 'IA32_DCA_0_CAP',
            # @defgroup ia32_mtrr_physbase \
            #           IA32_MTRR_PHYSBASE(n)
            # BEGIN
            0x00000200 : 'IA32_MTRR_PHYSBASE0',
            0x00000202 : 'IA32_MTRR_PHYSBASE1',
            0x00000204 : 'IA32_MTRR_PHYSBASE2',
            0x00000206 : 'IA32_MTRR_PHYSBASE3',
            0x00000208 : 'IA32_MTRR_PHYSBASE4',
            0x0000020A : 'IA32_MTRR_PHYSBASE5',
            0x0000020C : 'IA32_MTRR_PHYSBASE6',
            0x0000020E : 'IA32_MTRR_PHYSBASE7',
            0x00000210 : 'IA32_MTRR_PHYSBASE8',
            0x00000212 : 'IA32_MTRR_PHYSBASE9',
            # END

            # @defgroup ia32_mtrr_physmask \
            #           IA32_MTRR_PHYSMASK(n)
            # BEGIN
            0x00000201 : 'IA32_MTRR_PHYSMASK0',
            0x00000203 : 'IA32_MTRR_PHYSMASK1',
            0x00000205 : 'IA32_MTRR_PHYSMASK2',
            0x00000207 : 'IA32_MTRR_PHYSMASK3',
            0x00000209 : 'IA32_MTRR_PHYSMASK4',
            0x0000020B : 'IA32_MTRR_PHYSMASK5',
            0x0000020D : 'IA32_MTRR_PHYSMASK6',
            0x0000020F : 'IA32_MTRR_PHYSMASK7',
            0x00000211 : 'IA32_MTRR_PHYSMASK8',
            0x00000213 : 'IA32_MTRR_PHYSMASK9',
            # END

            # @defgroup ia32_mtrr_fix \
            #           IA32_MTRR_FIX(x)
            # BEGIN
            # @defgroup ia32_mtrr_fix64k \
            #           IA32_MTRR_FIX64K(x)
            # BEGIN
            0x00000000 : 'IA32_MTRR_FIX64K_BASE',
            0x00010000 : 'IA32_MTRR_FIX64K_SIZE',
            0x00000250 : 'IA32_MTRR_FIX64K_00000',
            # END

            # @defgroup ia32_mtrr_fix16k \
            #           IA32_MTRR_FIX16K(x)
            # BEGIN
            0x00080000 : 'IA32_MTRR_FIX16K_BASE',
            0x00004000 : 'IA32_MTRR_FIX16K_SIZE',
            0x00000258 : 'IA32_MTRR_FIX16K_80000',
            0x00000259 : 'IA32_MTRR_FIX16K_A0000',
            # END

            # @defgroup ia32_mtrr_fix4k \
            #           IA32_MTRR_FIX4K(x)
            # BEGIN
            0x000C0000 : 'IA32_MTRR_FIX4K_BASE',
            0x00001000 : 'IA32_MTRR_FIX4K_SIZE',
            0x00000268 : 'IA32_MTRR_FIX4K_C0000',
            0x00000269 : 'IA32_MTRR_FIX4K_C8000',
            0x0000026A : 'IA32_MTRR_FIX4K_D0000',
            0x0000026B : 'IA32_MTRR_FIX4K_D8000',
            0x0000026C : 'IA32_MTRR_FIX4K_E0000',
            0x0000026D : 'IA32_MTRR_FIX4K_E8000',
            0x0000026E : 'IA32_MTRR_FIX4K_F0000',
            0x0000026F : 'IA32_MTRR_FIX4K_F8000',
            # END


            # """
            # >>> hex(((1 + 2 + 8) * 8))
            # '0x58'
            # """
            # '((1 + 2 + 8) * 8) : 'IA32_MTRR_FIX_COUNT',

            0x00000058 : 'IA32_MTRR_FIX_COUNT',
            0x000000FF : 'IA32_MTRR_VARIABLE_COUNT',
            # """>>> hex(0x00000058 + 0x000000FF)
            # '0x157'
            # """
            # '(IA32_MTRR_FIX_COUNT + IA32_MTRR_VARIABLE_COUNT) : 'IA32_MTRR_COUNT',
            0x00000157 : 'IA32_MTRR_COUNT',

            # END

            0x00000277 : 'IA32_PAT',
            # @defgroup ia32_mc_ctl2 \
            #           IA32_MC(i)_CTL2
            # BEGIN
            0x00000280 : 'IA32_MC0_CTL2',
            0x00000281 : 'IA32_MC1_CTL2',
            0x00000282 : 'IA32_MC2_CTL2',
            0x00000283 : 'IA32_MC3_CTL2',
            0x00000284 : 'IA32_MC4_CTL2',
            0x00000285 : 'IA32_MC5_CTL2',
            0x00000286 : 'IA32_MC6_CTL2',
            0x00000287 : 'IA32_MC7_CTL2',
            0x00000288 : 'IA32_MC8_CTL2',
            0x00000289 : 'IA32_MC9_CTL2',
            0x0000028A : 'IA32_MC10_CTL2',
            0x0000028B : 'IA32_MC11_CTL2',
            0x0000028C : 'IA32_MC12_CTL2',
            0x0000028D : 'IA32_MC13_CTL2',
            0x0000028E : 'IA32_MC14_CTL2',
            0x0000028F : 'IA32_MC15_CTL2',
            0x00000290 : 'IA32_MC16_CTL2',
            0x00000291 : 'IA32_MC17_CTL2',
            0x00000292 : 'IA32_MC18_CTL2',
            0x00000293 : 'IA32_MC19_CTL2',
            0x00000294 : 'IA32_MC20_CTL2',
            0x00000295 : 'IA32_MC21_CTL2',
            0x00000296 : 'IA32_MC22_CTL2',
            0x00000297 : 'IA32_MC23_CTL2',
            0x00000298 : 'IA32_MC24_CTL2',
            0x00000299 : 'IA32_MC25_CTL2',
            0x0000029A : 'IA32_MC26_CTL2',
            0x0000029B : 'IA32_MC27_CTL2',
            0x0000029C : 'IA32_MC28_CTL2',
            0x0000029D : 'IA32_MC29_CTL2',
            0x0000029E : 'IA32_MC30_CTL2',
            0x0000029F : 'IA32_MC31_CTL2',
            # END

            0x000002FF : 'IA32_MTRR_DEF_TYPE',
            # @defgroup ia32_fixed_ctr \
            #           IA32_FIXED_CTR(n)
            # BEGIN
            0x00000309 : 'IA32_FIXED_CTR0',
            0x0000030A : 'IA32_FIXED_CTR1',
            0x0000030B : 'IA32_FIXED_CTR2',
            # END

            0x00000345 : 'IA32_PERF_CAPABILITIES',
            0x0000038D : 'IA32_FIXED_CTR_CTRL',
            0x0000038E : 'IA32_PERF_GLOBAL_STATUS',
            0x0000038F : 'IA32_PERF_GLOBAL_CTRL',
            0x00000390 : 'IA32_PERF_GLOBAL_STATUS_RESET',
            0x00000391 : 'IA32_PERF_GLOBAL_STATUS_SET',
            0x00000392 : 'IA32_PERF_GLOBAL_INUSE',
            0x000003F1 : 'IA32_PEBS_ENABLE',
            # @defgroup ia32_mc_ctl \
            #           IA32_MC(i)_CTL
            # BEGIN
            0x00000400 : 'IA32_MC0_CTL',
            0x00000404 : 'IA32_MC1_CTL',
            0x00000408 : 'IA32_MC2_CTL',
            0x0000040C : 'IA32_MC3_CTL',
            0x00000410 : 'IA32_MC4_CTL',
            0x00000414 : 'IA32_MC5_CTL',
            0x00000418 : 'IA32_MC6_CTL',
            0x0000041C : 'IA32_MC7_CTL',
            0x00000420 : 'IA32_MC8_CTL',
            0x00000424 : 'IA32_MC9_CTL',
            0x00000428 : 'IA32_MC10_CTL',
            0x0000042C : 'IA32_MC11_CTL',
            0x00000430 : 'IA32_MC12_CTL',
            0x00000434 : 'IA32_MC13_CTL',
            0x00000438 : 'IA32_MC14_CTL',
            0x0000043C : 'IA32_MC15_CTL',
            0x00000440 : 'IA32_MC16_CTL',
            0x00000444 : 'IA32_MC17_CTL',
            0x00000448 : 'IA32_MC18_CTL',
            0x0000044C : 'IA32_MC19_CTL',
            0x00000450 : 'IA32_MC20_CTL',
            0x00000454 : 'IA32_MC21_CTL',
            0x00000458 : 'IA32_MC22_CTL',
            0x0000045C : 'IA32_MC23_CTL',
            0x00000460 : 'IA32_MC24_CTL',
            0x00000464 : 'IA32_MC25_CTL',
            0x00000468 : 'IA32_MC26_CTL',
            0x0000046C : 'IA32_MC27_CTL',
            0x00000470 : 'IA32_MC28_CTL',
            # END

            # @defgroup ia32_mc_status \
            #           IA32_MC(i)_STATUS
            # BEGIN
            0x00000401 : 'IA32_MC0_STATUS',
            0x00000405 : 'IA32_MC1_STATUS',
            0x00000409 : 'IA32_MC2_STATUS',
            0x0000040D : 'IA32_MC3_STATUS',
            0x00000411 : 'IA32_MC4_STATUS',
            0x00000415 : 'IA32_MC5_STATUS',
            0x00000419 : 'IA32_MC6_STATUS',
            0x0000041D : 'IA32_MC7_STATUS',
            0x00000421 : 'IA32_MC8_STATUS',
            0x00000425 : 'IA32_MC9_STATUS',
            0x00000429 : 'IA32_MC10_STATUS',
            0x0000042D : 'IA32_MC11_STATUS',
            0x00000431 : 'IA32_MC12_STATUS',
            0x00000435 : 'IA32_MC13_STATUS',
            0x00000439 : 'IA32_MC14_STATUS',
            0x0000043D : 'IA32_MC15_STATUS',
            0x00000441 : 'IA32_MC16_STATUS',
            0x00000445 : 'IA32_MC17_STATUS',
            0x00000449 : 'IA32_MC18_STATUS',
            0x0000044D : 'IA32_MC19_STATUS',
            0x00000451 : 'IA32_MC20_STATUS',
            0x00000455 : 'IA32_MC21_STATUS',
            0x00000459 : 'IA32_MC22_STATUS',
            0x0000045D : 'IA32_MC23_STATUS',
            0x00000461 : 'IA32_MC24_STATUS',
            0x00000465 : 'IA32_MC25_STATUS',
            0x00000469 : 'IA32_MC26_STATUS',
            0x0000046D : 'IA32_MC27_STATUS',
            0x00000471 : 'IA32_MC28_STATUS',
            # END

            # @defgroup ia32_mc_addr \
            #           IA32_MC(i)_ADDR
            # BEGIN
            0x00000402 : 'IA32_MC0_ADDR',
            0x00000406 : 'IA32_MC1_ADDR',
            0x0000040A : 'IA32_MC2_ADDR',
            0x0000040E : 'IA32_MC3_ADDR',
            0x00000412 : 'IA32_MC4_ADDR',
            0x00000416 : 'IA32_MC5_ADDR',
            0x0000041A : 'IA32_MC6_ADDR',
            0x0000041E : 'IA32_MC7_ADDR',
            0x00000422 : 'IA32_MC8_ADDR',
            0x00000426 : 'IA32_MC9_ADDR',
            0x0000042A : 'IA32_MC10_ADDR',
            0x0000042E : 'IA32_MC11_ADDR',
            0x00000432 : 'IA32_MC12_ADDR',
            0x00000436 : 'IA32_MC13_ADDR',
            0x0000043A : 'IA32_MC14_ADDR',
            0x0000043E : 'IA32_MC15_ADDR',
            0x00000442 : 'IA32_MC16_ADDR',
            0x00000446 : 'IA32_MC17_ADDR',
            0x0000044A : 'IA32_MC18_ADDR',
            0x0000044E : 'IA32_MC19_ADDR',
            0x00000452 : 'IA32_MC20_ADDR',
            0x00000456 : 'IA32_MC21_ADDR',
            0x0000045A : 'IA32_MC22_ADDR',
            0x0000045E : 'IA32_MC23_ADDR',
            0x00000462 : 'IA32_MC24_ADDR',
            0x00000466 : 'IA32_MC25_ADDR',
            0x0000046A : 'IA32_MC26_ADDR',
            0x0000046E : 'IA32_MC27_ADDR',
            0x00000472 : 'IA32_MC28_ADDR',
            # END

            # @defgroup ia32_mc_misc \
            #           IA32_MC(i)_MISC
            # BEGIN
            0x00000403 : 'IA32_MC0_MISC',
            0x00000407 : 'IA32_MC1_MISC',
            0x0000040B : 'IA32_MC2_MISC',
            0x0000040F : 'IA32_MC3_MISC',
            0x00000413 : 'IA32_MC4_MISC',
            0x00000417 : 'IA32_MC5_MISC',
            0x0000041B : 'IA32_MC6_MISC',
            0x0000041F : 'IA32_MC7_MISC',
            0x00000423 : 'IA32_MC8_MISC',
            0x00000427 : 'IA32_MC9_MISC',
            0x0000042B : 'IA32_MC10_MISC',
            0x0000042F : 'IA32_MC11_MISC',
            0x00000433 : 'IA32_MC12_MISC',
            0x00000437 : 'IA32_MC13_MISC',
            0x0000043B : 'IA32_MC14_MISC',
            0x0000043F : 'IA32_MC15_MISC',
            0x00000443 : 'IA32_MC16_MISC',
            0x00000447 : 'IA32_MC17_MISC',
            0x0000044B : 'IA32_MC18_MISC',
            0x0000044F : 'IA32_MC19_MISC',
            0x00000453 : 'IA32_MC20_MISC',
            0x00000457 : 'IA32_MC21_MISC',
            0x0000045B : 'IA32_MC22_MISC',
            0x0000045F : 'IA32_MC23_MISC',
            0x00000463 : 'IA32_MC24_MISC',
            0x00000467 : 'IA32_MC25_MISC',
            0x0000046B : 'IA32_MC26_MISC',
            0x0000046F : 'IA32_MC27_MISC',
            0x00000473 : 'IA32_MC28_MISC',
            # END

            0x00000480 : 'IA32_VMX_BASIC',
            0x00000481 : 'IA32_VMX_PINBASED_CTLS',
            0x00000482 : 'IA32_VMX_PROCBASED_CTLS',
            0x00000483 : 'IA32_VMX_EXIT_CTLS',
            0x00000484 : 'IA32_VMX_ENTRY_CTLS',
            0x00000485 : 'IA32_VMX_MISC',
            0x00000486 : 'IA32_VMX_CR0_FIXED0',
            0x00000487 : 'IA32_VMX_CR0_FIXED1',
            0x00000488 : 'IA32_VMX_CR4_FIXED0',
            0x00000489 : 'IA32_VMX_CR4_FIXED1',
            0x0000048A : 'IA32_VMX_VMCS_ENUM',
            0x0000048B : 'IA32_VMX_PROCBASED_CTLS2',
            0x0000048C : 'IA32_VMX_EPT_VPID_CAP',
            # @defgroup ia32_vmx_true_ctls \
            #           IA32_VMX_TRUE_(x)_CTLS
            # BEGIN
            0x0000048D : 'IA32_VMX_TRUE_PINBASED_CTLS',
            0x0000048E : 'IA32_VMX_TRUE_PROCBASED_CTLS',
            0x0000048F : 'IA32_VMX_TRUE_EXIT_CTLS',
            0x00000490 : 'IA32_VMX_TRUE_ENTRY_CTLS',
            # END

            0x00000491 : 'IA32_VMX_VMFUNC',
            # @defgroup ia32_a_pmc \
            #           IA32_A_PMC(n)
            # BEGIN
            0x000004C1 : 'IA32_A_PMC0',
            0x000004C2 : 'IA32_A_PMC1',
            0x000004C3 : 'IA32_A_PMC2',
            0x000004C4 : 'IA32_A_PMC3',
            0x000004C5 : 'IA32_A_PMC4',
            0x000004C6 : 'IA32_A_PMC5',
            0x000004C7 : 'IA32_A_PMC6',
            0x000004C8 : 'IA32_A_PMC7',
            # END

            0x000004D0 : 'IA32_MCG_EXT_CTL',
            0x00000500 : 'IA32_SGX_SVN_STATUS',
            0x00000560 : 'IA32_RTIT_OUTPUT_BASE',
            0x00000561 : 'IA32_RTIT_OUTPUT_MASK_PTRS',
            0x00000570 : 'IA32_RTIT_CTL',
            0x00000571 : 'IA32_RTIT_STATUS',
            0x00000572 : 'IA32_RTIT_CR3_MATCH',
            # @defgroup ia32_rtit_addr \
            #           IA32_RTIT_ADDR(x)
            # BEGIN
            # @defgroup ia32_rtit_addr_a \
            #           IA32_RTIT_ADDR(n)_A
            # BEGIN
            0x00000580 : 'IA32_RTIT_ADDR0_A',
            0x00000582 : 'IA32_RTIT_ADDR1_A',
            0x00000584 : 'IA32_RTIT_ADDR2_A',
            0x00000586 : 'IA32_RTIT_ADDR3_A',
            # END

            # @defgroup ia32_rtit_addr_b \
            #           IA32_RTIT_ADDR(n)_B
            # BEGIN
            0x00000581 : 'IA32_RTIT_ADDR0_B',
            0x00000583 : 'IA32_RTIT_ADDR1_B',
            0x00000585 : 'IA32_RTIT_ADDR2_B',
            0x00000587 : 'IA32_RTIT_ADDR3_B',
            # END

            # END

            0x00000600 : 'IA32_DS_AREA',
            0x000006E0 : 'IA32_TSC_DEADLINE',
            0x00000770 : 'IA32_PM_ENABLE',
            0x00000771 : 'IA32_HWP_CAPABILITIES',
            0x00000772 : 'IA32_HWP_REQUEST_PKG',
            0x00000773 : 'IA32_HWP_INTERRUPT',
            0x00000774 : 'IA32_HWP_REQUEST',
            0x00000777 : 'IA32_HWP_STATUS',
            0x00000802 : 'IA32_X2APIC_APICID',
            0x00000803 : 'IA32_X2APIC_VERSION',
            0x00000808 : 'IA32_X2APIC_TPR',
            0x0000080A : 'IA32_X2APIC_PPR',
            0x0000080B : 'IA32_X2APIC_EOI',
            0x0000080D : 'IA32_X2APIC_LDR',
            0x0000080F : 'IA32_X2APIC_SIVR',
            # @defgroup ia32_x2apic_isr \
            #           IA32_X2APIC_ISR(n)
            # BEGIN
            0x00000810 : 'IA32_X2APIC_ISR0',
            0x00000811 : 'IA32_X2APIC_ISR1',
            0x00000812 : 'IA32_X2APIC_ISR2',
            0x00000813 : 'IA32_X2APIC_ISR3',
            0x00000814 : 'IA32_X2APIC_ISR4',
            0x00000815 : 'IA32_X2APIC_ISR5',
            0x00000816 : 'IA32_X2APIC_ISR6',
            0x00000817 : 'IA32_X2APIC_ISR7',
            # END

            # @defgroup ia32_x2apic_tmr \
            #           IA32_X2APIC_TMR(n)
            # BEGIN
            0x00000818 : 'IA32_X2APIC_TMR0',
            0x00000819 : 'IA32_X2APIC_TMR1',
            0x0000081A : 'IA32_X2APIC_TMR2',
            0x0000081B : 'IA32_X2APIC_TMR3',
            0x0000081C : 'IA32_X2APIC_TMR4',
            0x0000081D : 'IA32_X2APIC_TMR5',
            0x0000081E : 'IA32_X2APIC_TMR6',
            0x0000081F : 'IA32_X2APIC_TMR7',
            # END

            # @defgroup ia32_x2apic_irr \
            #           IA32_X2APIC_IRR(n)
            # BEGIN
            0x00000820 : 'IA32_X2APIC_IRR0',
            0x00000821 : 'IA32_X2APIC_IRR1',
            0x00000822 : 'IA32_X2APIC_IRR2',
            0x00000823 : 'IA32_X2APIC_IRR3',
            0x00000824 : 'IA32_X2APIC_IRR4',
            0x00000825 : 'IA32_X2APIC_IRR5',
            0x00000826 : 'IA32_X2APIC_IRR6',
            0x00000827 : 'IA32_X2APIC_IRR7',
            # END

            0x00000828 : 'IA32_X2APIC_ESR',
            0x0000082F : 'IA32_X2APIC_LVT_CMCI',
            0x00000830 : 'IA32_X2APIC_ICR',
            0x00000832 : 'IA32_X2APIC_LVT_TIMER',
            0x00000833 : 'IA32_X2APIC_LVT_THERMAL',
            0x00000834 : 'IA32_X2APIC_LVT_PMI',
            0x00000835 : 'IA32_X2APIC_LVT_LINT0',
            0x00000836 : 'IA32_X2APIC_LVT_LINT1',
            0x00000837 : 'IA32_X2APIC_LVT_ERROR',
            0x00000838 : 'IA32_X2APIC_INIT_COUNT',
            0x00000839 : 'IA32_X2APIC_CUR_COUNT',
            0x0000083E : 'IA32_X2APIC_DIV_CONF',
            0x0000083F : 'IA32_X2APIC_SELF_IPI',
            0x00000C80 : 'IA32_DEBUG_INTERFACE',
            0x00000C81 : 'IA32_L3_QOS_CFG',
            0x00000C82 : 'IA32_L2_QOS_CFG',
            0x00000C8D : 'IA32_QM_EVTSEL',
            0x00000C8E : 'IA32_QM_CTR',
            0x00000C8F : 'IA32_PQR_ASSOC',
            0x00000D90 : 'IA32_BNDCFGS',
            0x00000DA0 : 'IA32_XSS',
            0x00000DB0 : 'IA32_PKG_HDC_CTL',
            0x00000DB1 : 'IA32_PM_CTL1',
            0x00000DB2 : 'IA32_THREAD_STALL',
            0xC0000080 : 'IA32_EFER',
            0xC0000081 : 'IA32_STAR',
            0xC0000082 : 'IA32_LSTAR',
            0xC0000083 : 'IA32_CSTAR',
            0xC0000084 : 'IA32_FMASK',
            0xC0000100 : 'IA32_FS_BASE',
            0xC0000101 : 'IA32_GS_BASE',
            0xC0000102 : 'IA32_KERNEL_GS_BASE',
            0xC0000103 : 'IA32_TSC_AUX',
            # END

            # end https://github.com/wbenny/ia32-doc
            #######################################################
        }

    def GetIa32VmcsDb(self):
        return self.ia32_vmcs_db

    def GetIa32MsrDb(self):
        return self.ia32_msr_db

# ------------------------------------------------------------------------------------- #
def PrettyHex(v):
    return '0x{0:08X}'.format(v)

def GetJumpAddr(call_addr, func_ea):
    func_addr = idc.LocByName(idc.GetFunctionName(func_ea))
    ret = int(call_addr - func_addr)
    return hex(ret).replace("0x", "")

def GetFunctionNamePlusRva(inst_ea):
        jump_addr = GetJumpAddr(inst_ea, inst_ea)
        return idc.GetFunctionName(inst_ea)+ '+' + jump_addr


def AddressToHex(ea):
    return hex(ea).rstrip('L')

def GetDelimeter(input_str,max_len = 30, delim_char = " "):
    if input_str == None:
        return delim_char * (max_len - len('NoneNone'))
    else:
        return delim_char * (max_len - len(input_str))

def GetValueWithDelimeter(input_str,max_len = 30, delim_char = " "):
    if input_str == None:
        return GetDelimeter(input_str,max_len,delim_char)
    return input_str+GetDelimeter(input_str,max_len,delim_char)

# ------------------------------------------------------------------------------------- #
class Config (object):
    PLUGIN_TITLTE = "IA32 VMX Helper"
    COLUMN_NAMES  = ["Address", "Mnemonic",  "Value_Hex", "Value_Name", "Function_Name"]
    COLUMN_SIZE   = [20,     10,         18, 40 , 30]
    PLUGIN_COLUMNS = [list(c) for c in
                      zip(COLUMN_NAMES, COLUMN_SIZE)]

    ROW_ITEM = collections.namedtuple("RowItem",  COLUMN_NAMES)

class PluginPage(idaapi.Choose2):
    
    def __init__(self, title, columns, items, icon, embedded=False):

        idaapi.Choose2.__init__(self, title, columns, embedded=embedded)
        self.items = items
        self.icon = icon

    def GetItems(self):
        return self.items

    def SetItems(self, items):
        self.items = [] if items is None else items
        self.Refresh()

    def OnClose(self):
        pass

    def OnGetLine(self, index):
        return self.items[index]

    def OnGetSize(self):
        return len(self.items)

    def OnSelectLine(self, index):
        try:
            row = self.items[index][0]
            addr = int(row,16)
            idc.Jump(addr)
        except Exception, e:
            idc.Warning('Exception : Selected item {}  = {}'.format(index,str(e))) 
            pass





class ReportEntry(object):
    
    def __init__(self, addr,mnemonic,value_hex,value_name,func_name):
        self.addr = addr
        self.mnemonic = mnemonic
        self.value_hex = value_hex
        self.value_name = value_name
        self.func_name = func_name

    def get_row(self):

        addr = "0x%x" % (self.addr)
        return list(Config.ROW_ITEM(addr, self.mnemonic, self.value_hex,self.value_name,self.func_name))

# ------------------------------------------------------------------------------------- #

def GetEnumItemByConst(const_value,constants):
    if constants == None:
        # idc.Warning('constants not loaded')
        return None
    for item_name,item_constant, enum_id in constants:
        if item_constant == const_value:
            return [item_name,enum_id]
    return None

class SymbolicConstant(object):
    def __init__(self,enum_name):
        self.enum_name = enum_name
        self.result = []
        self.count = 0

    def LoadEnums(self):
        enum_id = idc.GetEnum(self.enum_name)
        enum_count = idc.GetEnumSize(enum_id)
        
        if enum_id == idaapi.BADADDR:
            return None

        item_constant = idc.GetFirstConst(enum_id, -1)
        item_name     = idc.GetConstName(idc.GetConstEx(enum_id, item_constant, 0, -1))

        self.result.append([item_name,item_constant, enum_id])

        for i in range(enum_count):
            item_constant = idc.GetNextConst(enum_id, item_constant, -1)
            item_name = idc.GetConstName(idc.GetConstEx(enum_id, item_constant, 0, -1))

            self.result.append([item_name,item_constant, enum_id])

        return self.result
# ------------------------------------------------------------------------------------- #
OPERAND_INDEX_0 = 0
OPERAND_INDEX_1 = 1

class Instruction_t(object):
    def __init__(self,inst_ea):
        self.inst_ea = inst_ea
        self.mnemonic = idc.GetMnem(self.inst_ea)
        self.operand_0 = idc.GetOpnd(self.inst_ea, 0)
        self.operand_1 = idc.GetOpnd(self.inst_ea, 1)

        self.operand_value_0 = idc.GetOperandValue(self.inst_ea,0)
        self.operand_value_1 = idc.GetOperandValue(self.inst_ea,1)

    def GetOperandValue_32bit(self,operand_index):
        return idc.GetOperandValue(self.inst_ea,operand_index) & 0xffffffff

    def GetOperandType(self,operand_index):
        return idc.GetOpType(self.inst_ea,operand_index)
    
    @property
    def NextInstruction(self):
        return Instruction_t(idc.NextHead(self.inst_ea))

    @property
    def PrevInstruction(self):
        return Instruction_t(idc.PrevHead(self.inst_ea))
    
    @property
    def FunctionName(self):
        return idc.GetFunctionName(self.inst_ea)

    def IsCode(self):
        return idaapi.isCode(idaapi.getFlags(self.inst_ea))

    def IsCallInstruction(self):
        return self.mnemonic == 'call'

    def GetRvaFromBaseOfFunction(self):
        func_ea = idc.LocByName(self.FunctionName)
        return int(self.inst_ea - func_ea)

    def IsXoredThisReg(self,reg):
        return self.mnemonic == 'xor' and self.operand_0 == self.operand_1 == reg;

    def IsXoredWithItself(self):
        return self.mnemonic == 'xor' and self.operand_0 == self.operand_1;

# ------------------------------------------------------------------------------------- #
# @ IA32 MSR ANALYZER BEGIN ==>
# ------------------------------------------------------------------------------------- #
class Ia32MsrAnalyzePass(object):
    def __init__(self,func_ea,symbolic_constants,enable_symbolic_constants = False,enable_comment = False, \
        enable_colorize = False , color = 0x00441E):

        self.func_ea = func_ea
        self.inst_ea = None

        self.symbolic_constants = symbolic_constants

        self.ia32_msr_db = g_knowledge_db.GetIa32MsrDb()

        self.enable_symbolic_constants = enable_symbolic_constants
        self.enable_comment = enable_comment
        self.enable_colorize = enable_colorize
        self.color = color

        self.msr_code_imm_ea = None

        self.gui_report_rows = []

    def IsVmxInstruction(self,inst_ea):
        mnemonic = idc.GetMnem(inst_ea)
        return mnemonic =='rdmsr' or mnemonic=='wrmsr'

    def SetSymbolcsConstantOfMsrCode(self,inst_ea,msr_code):
        ret = GetEnumItemByConst(msr_code,self.symbolic_constants)
        if ret == None: 
            return
        item_name, enum_id = ret
        if enum_id  and self.ia32_msr_db.get(msr_code)== item_name:
            idc.OpEnumEx(inst_ea, 1,enum_id,0 )

    def GetMsrCodeFromOperand(self,inst_ea):
        curr_inst = Instruction_t(inst_ea)

        while True:
            curr_inst = curr_inst.PrevInstruction
            if(curr_inst.mnemonic == 'mov' and curr_inst.operand_0[-2:] == 'cx'):
                if (curr_inst.GetOperandType(OPERAND_INDEX_1) == idc.o_reg and cfg_enable_smart_mode == True):
                    reg_name = curr_inst.operand_1
                    rev_inst = Instruction_t(curr_inst.inst_ea)

                    if(reg_name[-2:] == 'ax' and rev_inst.PrevInstruction.IsCallInstruction()):
                        """
                        rcx value came from a function call

                        mov     r10d, 0A0013h
                        mov     ecx, r10d
                        call    sub_FFFFF800002E7C78
                        mov     ecx, eax
                        rdmsr                   ; rdmsr(Not imm value) 
                        """
                        return None

                    """
                    mov rax, 0xC0000082 ; IA32_LSTAR
                    mov rcx,rax
                    """
                    for i in range(cfg_smart_mode_max_back_step):
                        rev_inst = rev_inst.PrevInstruction 
                        if rev_inst.mnemonic == 'mov' and rev_inst.operand_0 == reg_name and \
                            rev_inst.GetOperandType(OPERAND_INDEX_1) == idc.o_imm:

                            self.msr_code_imm_ea = rev_inst.inst_ea
                            return rev_inst.GetOperandValue_32bit(OPERAND_INDEX_1)

                # mov rcx, 0xC0000082 ; IA32_LSTAR
                elif(curr_inst.GetOperandType(OPERAND_INDEX_1) == idc.o_imm):
                    self.msr_code_imm_ea = curr_inst.inst_ea
                    return curr_inst.GetOperandValue_32bit(OPERAND_INDEX_1)
                    
            # Not imm value :-(
            elif (curr_inst.mnemonic == 'lea' and  curr_inst.operand_0 in ['rcx','ecx']):
                return None
            # xor rcx,rcx 
            elif (curr_inst.operand_0 in ['rcx','ecx'] and curr_inst.IsXoredThisReg(curr_inst.operand_0)):
                self.msr_code_imm_ea = curr_inst.inst_ea
                return 0
            else:
                continue

    def GetMsrName(self,msr_code):
        name = self.ia32_msr_db.get(msr_code)
        if (name == None):
            name = PrettyHex(msr_code)
        return name

    def GetGuiReportRows(self):
        return self.gui_report_rows

    def RunPass(self):
        for self.inst_ea in idautils.FuncItems(self.func_ea):
            mnemonic = idc.GetMnem(self.inst_ea)
            if (self.IsVmxInstruction(self.inst_ea) == False):
                continue

            msr_name = None
            msr_hex  = None
            msr_code = self.GetMsrCodeFromOperand(self.inst_ea)

            if(msr_code == None):
                msr_name = 'Not imm value'
                msr_hex  = 'Not imm value'
            else:
                msr_name = self.GetMsrName(msr_code)
                msr_hex  = PrettyHex(msr_code)

            if(self.enable_comment):
                comment_message = '{}({})'.format(mnemonic,msr_name)
                idc.MakeComm(self.inst_ea, comment_message)
            
            if(self.enable_colorize):
                idc.SetColor(self.inst_ea,idc.CIC_ITEM, self.color)

            if(self.enable_symbolic_constants and msr_code != None):
                self.SetSymbolcsConstantOfMsrCode(self.msr_code_imm_ea,msr_code)

            self.gui_report_rows.append(ReportEntry(
                                        self.inst_ea,
                                        mnemonic,
                                        msr_hex,
                                        msr_name,
                                        GetFunctionNamePlusRva(self.inst_ea))
                                        )

# ------------------------------------------------------------------------------------- #
# @ IA32 MSR ANALYZER END <==
# ------------------------------------------------------------------------------------- #

# ------------------------------------------------------------------------------------- #
# @IA32 VMCS ANALYZER BEGIN ==>
# ------------------------------------------------------------------------------------- #

class Ia32VmcsAnalyzePass(object):
    def __init__(self,func_ea,symbolic_constants,enable_symbolic_constants = False, enable_comment = False, \
        enable_colorize = False , color = 0x00441E):

        self.func_ea = func_ea
        self.inst_ea = None

        self.symbolic_constants = symbolic_constants

        self.ia32_vmcs_db = g_knowledge_db.GetIa32VmcsDb()

        self.enable_symbolic_constants = enable_symbolic_constants
        self.enable_comment = enable_comment
        self.enable_colorize = enable_colorize
        self.color = color

        self.vmcs_code_imm_ea = None

        self.gui_report_rows = []

    def IsVmxInstruction(self,inst_ea):
        mnemonic = idc.GetMnem(inst_ea)
        return mnemonic =='vmread' or mnemonic=='vmwrite'

    def SetSymbolcsConstantOfVmcsCode(self,inst_ea,vmcs_code):
        ret = GetEnumItemByConst(vmcs_code,self.symbolic_constants)
        if ret == None: 
            return
        item_name, enum_id = ret
        if enum_id  and self.ia32_vmcs_db.get(vmcs_code)== item_name:
            idc.OpEnumEx(inst_ea, 1,enum_id,0 )

    def GetValueRegister(self,inst_ea):
        """
        vmread  buffer, vmcs_code
        vmwrite vmcs_code, buffer
        """
        inst_t = Instruction_t(inst_ea)
        if( inst_t.mnemonic == 'vmread' ):#and inst_t.GetOperandType(0) == idc.o_reg ):
            return inst_t.operand_0
        elif( inst_t.mnemonic == 'vmwrite'):# and inst_t.GetOperandType(1) == idc.o_reg ):
            return inst_t.operand_1
        else:
            return None

    def GetCodeRegister(self,inst_ea):
        """
        vmread  buffer, vmcs_code
        vmwrite vmcs_code, buffer
        """
        inst_t = Instruction_t(inst_ea)
        if( inst_t.mnemonic == 'vmread' and inst_t.GetOperandType(1) == idc.o_reg ):
            return inst_t.operand_1
        elif( inst_t.mnemonic == 'vmwrite' and inst_t.GetOperandType(0) == idc.o_reg ):
            return inst_t.operand_0
        else:
            return None

    def GetVmcsCodeFromOperand(self,inst_ea):
        curr_inst = Instruction_t(inst_ea)

        code_reg = self.GetCodeRegister(inst_ea)
        if( code_reg == None ):
            return None

        while True:
            curr_inst = curr_inst.PrevInstruction

            # mov  ['cx', 'ecx', 'rcx'] [-2:] ==> 'cx'  , ###
            if( curr_inst.mnemonic == 'mov' and curr_inst.operand_0[-2:] == code_reg[-2:]):
                if(curr_inst.GetOperandType(OPERAND_INDEX_1) == idc.o_imm):
                    self.vmcs_code_imm_ea = curr_inst.inst_ea
                    return curr_inst.GetOperandValue_32bit(OPERAND_INDEX_1)

                # if mov ecx, rcx keep looking for mov rax, imm
                elif(curr_inst.GetOperandType(OPERAND_INDEX_1) == idc.o_reg and cfg_enable_smart_mode == True):
                    reg_name = curr_inst.operand_1
                    rev_inst = Instruction_t(curr_inst.inst_ea)

                    if(reg_name[-2:] == 'ax' and rev_inst.PrevInstruction.IsCallInstruction()):
                        """
                        register value came from a function call
                        """
                        return None
                    
                    # while True:
                    for i in range(cfg_smart_mode_max_back_step):
                        rev_inst = rev_inst.PrevInstruction
                        if rev_inst.mnemonic == 'mov' and rev_inst.operand_0 == reg_name and \
                            rev_inst.GetOperandType(OPERAND_INDEX_1) == idc.o_imm:

                            self.vmcs_code_imm_ea = rev_inst.inst_ea
                            return rev_inst.GetOperandValue_32bit(OPERAND_INDEX_1)

            # Not imm value :-(
            elif (curr_inst.mnemonic == 'lea' and curr_inst.operand_0[-2:] == code_reg[-2:]):
                return None
            # xor ecx,ecx means vmcs code is 0x0 VMCS_CTRL_VPID
            elif(curr_inst.operand_0[-2:] == code_reg[-2:] and curr_inst.IsXoredThisReg(code_reg)):
                self.vmcs_code_imm_ea = curr_inst.inst_ea
                return 0

    def GetVmcsName(self,vmcs_code):
        name = self.ia32_vmcs_db.get(vmcs_code)
        if (name == None):
            name = PrettyHex(vmcs_code)
        return name

    def GetGuiReportRows(self):
        return self.gui_report_rows

    def RunPass(self):
        for self.inst_ea in idautils.FuncItems(self.func_ea):
            mnemonic = idc.GetMnem(self.inst_ea)
            if (self.IsVmxInstruction(self.inst_ea) == False):
                continue

            vmcs_name = None
            vmcs_hex  = None
            vmcs_code = self.GetVmcsCodeFromOperand(self.inst_ea)

            if(vmcs_code == None):
                vmcs_name = 'Not imm value'
                vmcs_hex  = 'Not imm value'
            else:
                vmcs_name = self.GetVmcsName(vmcs_code)
                vmcs_hex  = PrettyHex(vmcs_code)

            if(self.enable_comment):
                comment_message = '{}({}, {})'.format(mnemonic,vmcs_name,self.GetValueRegister(self.inst_ea))
                idc.MakeComm(self.inst_ea, comment_message)
            
            if(self.enable_colorize):
                idc.SetColor(self.inst_ea,idc.CIC_ITEM, self.color)

            if(self.enable_symbolic_constants and vmcs_code != None):
                self.SetSymbolcsConstantOfVmcsCode(self.vmcs_code_imm_ea,vmcs_code)

            self.gui_report_rows.append(ReportEntry(
                                        self.inst_ea,
                                        mnemonic,
                                        vmcs_hex,
                                        vmcs_name,
                                        GetFunctionNamePlusRva(self.inst_ea))
                                        )

# ------------------------------------------------------------------------------------- #
# @IA32 VMCS ANALYZER END <==
# ------------------------------------------------------------------------------------- #

# ------------------------------------------------------------------------------------- #


class Ia32VmxHelper(idaapi.plugin_t):
    def __init__(self):
        self.enable_comment  = 0
        self.enable_colorize = 0
        self.enable_symbolic_constants = 0
        self.gui_report_rows = []

        self.ia32_msr_symbolic_constants = SymbolicConstant('IA32_MSR_LIST_ENUM').LoadEnums()
        self.ia32_vmcs_symbolic_constants = SymbolicConstant('IA32_VMCS_LIST_ENUM').LoadEnums()

        global g_knowledge_db
        g_knowledge_db = KnowledgeDb()

        flags = idaapi.PLUGIN_UNL
        comment = ''
        help = ''
        wanted_name = ''
        # wanted_hotkey = 'Ctrl-Alt-Q'

    def AddRowsToGuiTable(self,rows):
        if self._plugin_page is None:
            self._plugin_page = PluginPage(
                    Config.PLUGIN_TITLTE, Config.PLUGIN_COLUMNS,rows, self.icon_id)
        else:
            self._plugin_page.SetItems(rows)

        self._plugin_page.Show()

    def init(self):
        self._plugin_page = None
        self.icon_id = None
        return idaapi.PLUGIN_OK

    def term(self):
        pass

    def run(self,_=0):
        only_show = idc.AskYN(1,'Only show the result')
        if(only_show == 0):
            add_enums = idc.AskYN(0,'Do you want to add symbolic constants enums?, **You Only need to do this for once not more!**')
            if(add_enums == 1):
                AddSymbolicConstantsEnumsToIda()
                if(self.ia32_msr_symbolic_constants == None):
                    self.ia32_msr_symbolic_constants = SymbolicConstant('IA32_MSR_LIST_ENUM').LoadEnums()
                if(self.ia32_vmcs_symbolic_constants == None):
                    self.ia32_vmcs_symbolic_constants = SymbolicConstant('IA32_VMCS_LIST_ENUM').LoadEnums()

            self.enable_comment  = idc.AskYN(0,'Do you want to add comment on all decoded values?')
            self.enable_colorize = idc.AskYN(0,'Do you want to colorize all decoded values?')
            self.enable_symbolic_constants = idc.AskYN(0,'Do you want to apply symbolic constants on all decoded values?')

        for func_ea in idautils.Functions():
            isa32_msr_pass = Ia32MsrAnalyzePass(func_ea,
                                                self.ia32_msr_symbolic_constants,
                                                self.enable_symbolic_constants,
                                                self.enable_comment,
                                                self.enable_colorize,
                                                0x00441E)

            isa32_vmcs_pass = Ia32VmcsAnalyzePass(func_ea,
                                                self.ia32_vmcs_symbolic_constants,
                                                self.enable_symbolic_constants,
                                                self.enable_comment,
                                                self.enable_colorize,
                                                0x00441E)
            
            isa32_msr_pass.RunPass()
            isa32_vmcs_pass.RunPass()
            

            for i in isa32_msr_pass.GetGuiReportRows():
                 self.gui_report_rows.append(i.get_row())

            for i in isa32_vmcs_pass.GetGuiReportRows():
                 self.gui_report_rows.append(i.get_row())

        self.AddRowsToGuiTable(self.gui_report_rows)
# ------------------------------------------------------------------------------------- #
def PLUGIN_ENTRY():
    return Ia32VmxHelper()

def main():
    f = PLUGIN_ENTRY()
    f.init()
    f.run()
    f.term()

if __name__ == '__main__':
    main()
