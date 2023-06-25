#ifndef WINDOWS_TYPES_H
#define WINDOWS_TYPES_H

#define IMAGE_DOS_SIGNATURE                 0x5A4D
#define IMAGE_NT_SIGNATURE                  0x00004550
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[MAXIMUM_FILENAME_LENGTH];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE
{
	PULONG_PTR ServiceTableBase;
	PULONG ServiceCounterTableBase;
	ULONG_PTR NumberOfServices;
	PUCHAR ParamTableBase;
} SYSTEM_SERVICE_DESCRIPTOR_TABLE, * PSYSTEM_SERVICE_DESCRIPTOR_TABLE;

typedef unsigned long       DWORD;
typedef unsigned short      WORD;
typedef unsigned char       BYTE;

typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
	WORD   e_magic;                     // Magic number
	WORD   e_cblp;                      // Bytes on last page of file
	WORD   e_cp;                        // Pages file
	WORD   e_crlc;                      // Relocations
	WORD   e_cparhdr;                   // Size of header paragraphs
	WORD   e_minalloc;                  // Minimum extra paragraphs needed
	WORD   e_maxalloc;                  // Maximum extra paragraphs needed
	WORD   e_ss;                        // Initial (relative) SS value
	WORD   e_sp;                        // Initial SP value
	WORD   e_csum;                      // Checksum
	WORD   e_ip;                        // Initial IP value
	WORD   e_cs;                        // Initial (relative) CS value
	WORD   e_lfarlc;                    // File address of relocation table
	WORD   e_ovno;                      // Overlay number
	WORD   e_res[4];                    // Reserved words
	WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
	WORD   e_oeminfo;                   // OEM information; e_oemid specific
	WORD   e_res2[10];                  // Reserved words
	LONG   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
	WORD    Machine;
	WORD    NumberOfSections;
	DWORD   TimeDateStamp;
	DWORD   PointerToSymbolTable;
	DWORD   NumberOfSymbols;
	WORD    SizeOfOptionalHeader;
	WORD    Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
	ULONG   VirtualAddress;
	ULONG   Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_EXPORT_DIRECTORY {
	DWORD   Characteristics;
	DWORD   TimeDateStamp;
	WORD    MajorVersion;
	WORD    MinorVersion;
	DWORD   Name;
	DWORD   Base;
	DWORD   NumberOfFunctions;
	DWORD   NumberOfNames;
	DWORD   AddressOfFunctions;     // RVA from base of image
	DWORD   AddressOfNames;         // RVA from base of image
	DWORD   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER {
	WORD        Magic;
	BYTE        MajorLinkerVersion;
	BYTE        MinorLinkerVersion;
	DWORD       SizeOfCode;
	DWORD       SizeOfInitializedData;
	DWORD       SizeOfUninitializedData;
	DWORD       AddressOfEntryPoint;
	DWORD       BaseOfCode;
	ULONGLONG   ImageBase;
	DWORD       SectionAlignment;
	DWORD       FileAlignment;
	WORD        MajorOperatingSystemVersion;
	WORD        MinorOperatingSystemVersion;
	WORD        MajorImageVersion;
	WORD        MinorImageVersion;
	WORD        MajorSubsystemVersion;
	WORD        MinorSubsystemVersion;
	DWORD       Win32VersionValue;
	DWORD       SizeOfImage;
	DWORD       SizeOfHeaders;
	DWORD       CheckSum;
	WORD        Subsystem;
	WORD        DllCharacteristics;
	ULONGLONG   SizeOfStackReserve;
	ULONGLONG   SizeOfStackCommit;
	ULONGLONG   SizeOfHeapReserve;
	ULONGLONG   SizeOfHeapCommit;
	DWORD       LoaderFlags;
	DWORD       NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER, * PIMAGE_OPTIONAL_HEADER;

typedef struct _FULL_IMAGE_NT_HEADERS {
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER OptionalHeader;
} FULL_IMAGE_NT_HEADERS, * PFULL_IMAGE_NT_HEADERS;

typedef struct _IMAGE_SECTION_HEADER
{
	UCHAR  Name[8];
	union
	{
		ULONG PhysicalAddress;
		ULONG VirtualSize;
	} Misc;
	ULONG VirtualAddress;
	ULONG SizeOfRawData;
	ULONG PointerToRawData;
	ULONG PointerToRelocations;
	ULONG PointerToLinenumbers;
	USHORT  NumberOfRelocations;
	USHORT  NumberOfLinenumbers;
	ULONG Characteristics;
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;

typedef struct _SYSTEM_THREAD_INFORMATION
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	KWAIT_REASON WaitReason;
}SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFO
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_THREAD_INFORMATION Threads[1];
}SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;

enum SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemProcessorInformation = 1,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemPathInformation = 4,
	SystemProcessInformation = 5,
	SystemCallCountInformation = 6,
	SystemDeviceInformation = 7,
	SystemProcessorPerformanceInformation = 8,
	SystemFlagsInformation = 9,
	SystemCallTimeInformation = 10,
	SystemModuleInformation = 11,
	SystemLocksInformation = 12,
	SystemStackTraceInformation = 13,
	SystemPagedPoolInformation = 14,
	SystemNonPagedPoolInformation = 15,
	SystemHandleInformation = 16,
	SystemObjectInformation = 17,
	SystemPageFileInformation = 18,
	SystemVdmInstemulInformation = 19,
	SystemVdmBopInformation = 20,
	SystemFileCacheInformation = 21,
	SystemPoolTagInformation = 22,
	SystemInterruptInformation = 23,
	SystemDpcBehaviorInformation = 24,
	SystemFullMemoryInformation = 25,
	SystemLoadGdiDriverInformation = 26,
	SystemUnloadGdiDriverInformation = 27,
	SystemTimeAdjustmentInformation = 28,
	SystemSummaryMemoryInformation = 29,
	SystemMirrorMemoryInformation = 30,
	SystemPerformanceTraceInformation = 31,
	SystemObsolete0 = 32,
	SystemExceptionInformation = 33,
	SystemCrashDumpStateInformation = 34,
	SystemKernelDebuggerInformation = 35,
	SystemContextSwitchInformation = 36,
	SystemRegistryQuotaInformation = 37,
	SystemExtendServiceTableInformation = 38,
	SystemPrioritySeperation = 39,
	SystemVerifierAddDriverInformation = 40,
	SystemVerifierRemoveDriverInformation = 41,
	SystemProcessorIdleInformation = 42,
	SystemLegacyDriverInformation = 43,
	SystemCurrentTimeZoneInformation = 44,
	SystemLookasideInformation = 45,
	SystemTimeSlipNotification = 46,
	SystemSessionCreate = 47,
	SystemSessionDetach = 48,
	SystemSessionInformation = 49,
	SystemRangeStartInformation = 50,
	SystemVerifierInformation = 51,
	SystemVerifierThunkExtend = 52,
	SystemSessionProcessInformation = 53,
	SystemLoadGdiDriverInSystemSpace = 54,
	SystemNumaProcessorMap = 55,
	SystemPrefetcherInformation = 56,
	SystemExtendedProcessInformation = 57,
	SystemRecommendedSharedDataAlignment = 58,
	SystemComPlusPackage = 59,
	SystemNumaAvailableMemory = 60,
	SystemProcessorPowerInformation = 61,
	SystemEmulationBasicInformation = 62,
	SystemEmulationProcessorInformation = 63,
	SystemExtendedHandleInformation = 64,
	SystemLostDelayedWriteInformation = 65,
	SystemBigPoolInformation = 66,
	SystemSessionPoolTagInformation = 67,
	SystemSessionMappedViewInformation = 68,
	SystemHotpatchInformation = 69,
	SystemObjectSecurityMode = 70,
	SystemWatchdogTimerHandler = 71,
	SystemWatchdogTimerInformation = 72,
	SystemLogicalProcessorInformation = 73,
	SystemWow64SharedInformationObsolete = 74,
	SystemRegisterFirmwareTableInformationHandler = 75,
	SystemFirmwareTableInformation = 76,
	SystemModuleInformationEx = 77,
	SystemVerifierTriageInformation = 78,
	SystemSuperfetchInformation = 79,
	SystemMemoryListInformation = 80,
	SystemFileCacheInformationEx = 81,
	SystemThreadPriorityClientIdInformation = 82,
	SystemProcessorIdleCycleTimeInformation = 83,
	SystemVerifierCancellationInformation = 84,
	SystemProcessorPowerInformationEx = 85,
	SystemRefTraceInformation = 86,
	SystemSpecialPoolInformation = 87,
	SystemProcessIdInformation = 88,
	SystemErrorPortInformation = 89,
	SystemBootEnvironmentInformation = 90,
	SystemHypervisorInformation = 91,
	SystemVerifierInformationEx = 92,
	SystemTimeZoneInformation = 93,
	SystemImageFileExecutionOptionsInformation = 94,
	SystemCoverageInformation = 95,
	SystemPrefetchPatchInformation = 96,
	SystemVerifierFaultsInformation = 97,
	SystemSystemPartitionInformation = 98,
	SystemSystemDiskInformation = 99,
	SystemProcessorPerformanceDistribution = 100,
	SystemNumaProximityNodeInformation = 101,
	SystemDynamicTimeZoneInformation = 102,
	SystemCodeIntegrityInformation = 103,
	SystemProcessorMicrocodeUpdateInformation = 104,
	SystemProcessorBrandString = 105,
	SystemVirtualAddressInformation = 106,
	SystemLogicalProcessorAndGroupInformation = 107,
	SystemProcessorCycleTimeInformation = 108,
	SystemStoreInformation = 109,
	SystemRegistryAppendString = 110,
	SystemAitSamplingValue = 111,
	SystemVhdBootInformation = 112,
	SystemCpuQuotaInformation = 113,
	SystemNativeBasicInformation = 114,
	SystemErrorPortTimeouts = 115,
	SystemLowPriorityIoInformation = 116,
	SystemBootEntropyInformation = 117,
	SystemVerifierCountersInformation = 118,
	SystemPagedPoolInformationEx = 119,
	SystemSystemPtesInformationEx = 120,
	SystemNodeDistanceInformation = 121,
	SystemAcpiAuditInformation = 122,
	SystemBasicPerformanceInformation = 123,
	SystemQueryPerformanceCounterInformation = 124,
	SystemSessionBigPoolInformation = 125,
	SystemBootGraphicsInformation = 126,
	SystemScrubPhysicalMemoryInformation = 127,
	SystemBadPageInformation = 128,
	SystemProcessorProfileControlArea = 129,
	SystemCombinePhysicalMemoryInformation = 130,
	SystemEntropyInterruptTimingInformation = 131,
	SystemConsoleInformation = 132,
	SystemPlatformBinaryInformation = 133,
	SystemPolicyInformation = 134,
	SystemHypervisorProcessorCountInformation = 135,
	SystemDeviceDataInformation = 136,
	SystemDeviceDataEnumerationInformation = 137,
	SystemMemoryTopologyInformation = 138,
	SystemMemoryChannelInformation = 139,
	SystemBootLogoInformation = 140,
	SystemProcessorPerformanceInformationEx = 141,
	SystemCriticalProcessErrorLogInformation = 142,
	SystemSecureBootPolicyInformation = 143,
	SystemPageFileInformationEx = 144,
	SystemSecureBootInformation = 145,
	SystemEntropyInterruptTimingRawInformation = 146,
	SystemPortableWorkspaceEfiLauncherInformation = 147,
	SystemFullProcessInformation = 148,
	SystemKernelDebuggerInformationEx = 149,
	SystemBootMetadataInformation = 150,
	SystemSoftRebootInformation = 151,
	SystemElamCertificateInformation = 152,
	SystemOfflineDumpConfigInformation = 153,
	SystemProcessorFeaturesInformation = 154,
	SystemRegistryReconciliationInformation = 155,
	SystemEdidInformation = 156,
	SystemManufacturingInformation = 157,
	SystemEnergyEstimationConfigInformation = 158,
	SystemHypervisorDetailInformation = 159,
	SystemProcessorCycleStatsInformation = 160,
	SystemVmGenerationCountInformation = 161,
	SystemTrustedPlatformModuleInformation = 162,
	SystemKernelDebuggerFlags = 163,
	SystemCodeIntegrityPolicyInformation = 164,
	SystemIsolatedUserModeInformation = 165,
	SystemHardwareSecurityTestInterfaceResultsInformation = 166,
	SystemSingleModuleInformation = 167,
	SystemAllowedCpuSetsInformation = 168,
	SystemVsmProtectionInformation = 169,
	SystemInterruptCpuSetsInformation = 170,
	SystemSecureBootPolicyFullInformation = 171,
	SystemCodeIntegrityPolicyFullInformation = 172,
	SystemAffinitizedInterruptProcessorInformation = 173,
	SystemRootSiloInformation = 174,
	SystemCpuSetInformation = 175,
	SystemCpuSetTagInformation = 176,
	SystemWin32WerStartCallout = 177,
	SystemSecureKernelProfileInformation = 178,
	SystemCodeIntegrityPlatformManifestInformation = 179,
	SystemInterruptSteeringInformation = 180,
	SystemSupportedProcessorArchitectures = 181,
	SystemMemoryUsageInformation = 182,
	SystemCodeIntegrityCertificateInformation = 183,
	SystemPhysicalMemoryInformation = 184,
	SystemControlFlowTransition = 185,
	SystemKernelDebuggingAllowed = 186,
	SystemActivityModerationExeState = 187,
	SystemActivityModerationUserSettings = 188,
	SystemCodeIntegrityPoliciesFullInformation = 189,
	SystemCodeIntegrityUnlockInformation = 190,
	SystemIntegrityQuotaInformation = 191,
	SystemFlushInformation = 192,
	SystemProcessorIdleMaskInformation = 193,
	SystemSecureDumpEncryptionInformation = 194,
	SystemWriteConstraintInformation = 195,
	SystemKernelVaShadowInformation = 196,
	SystemHypervisorSharedPageInformation = 197,
	SystemFirmwareBootPerformanceInformation = 198,
	SystemCodeIntegrityVerificationInformation = 199,
	SystemFirmwarePartitionInformation = 200,
	SystemSpeculationControlInformation = 201,
	SystemDmaGuardPolicyInformation = 202,
	SystemEnclaveLaunchControlInformation = 203,
	SystemWorkloadAllowedCpuSetsInformation = 204,
	SystemCodeIntegrityUnlockModeInformation = 205,
	SystemLeapSecondInformation = 206,
	SystemFlags2Information = 207,
	SystemSecurityModelInformation = 208,
	SystemCodeIntegritySyntheticCacheInformation = 209,
	SystemFeatureConfigurationInformation = 210,
	SystemFeatureConfigurationSectionInformation = 211,
	SystemFeatureUsageSubscriptionInformation = 212,
	SystemSecureSpeculationControlInformation = 213,
	SystemSpacesBootInformation = 214,
	SystemFwRamdiskInformation = 215,
	SystemWheaIpmiHardwareInformation = 216,
	SystemDifSetRuleClassInformation = 217,
	SystemDifClearRuleClassInformation = 218,
	SystemDifApplyPluginVerificationOnDriver = 219,
	SystemDifRemovePluginVerificationOnDriver = 220,
	SystemShadowStackInformation = 221,
	SystemBuildVersionInformation = 222,
	SystemPoolLimitInformation = 223,
	SystemCodeIntegrityAddDynamicStore = 224,
	SystemCodeIntegrityClearDynamicStores = 225,
	SystemDifPoolTrackingInformation = 226,
	SystemPoolZeroingInformation = 227,
	SystemDpcWatchdogInformation = 228,
	SystemDpcWatchdogInformation2 = 229,
	SystemSupportedProcessorArchitectures2 = 230,
	SystemSingleProcessorRelationshipInformation = 231,
	SystemXfgCheckFailureInformation = 232,
	SystemIommuStateInformation = 233,
	SystemHypervisorMinrootInformation = 234,
	SystemHypervisorBootPagesInformation = 235,
	SystemPointerAuthInformation = 236,
	SystemSecureKernelDebuggerInformation = 237,
	SystemOriginalImageFeatureInformation = 238,
	MaxSystemInfoClass = 239
};

#pragma warning(default : 4214)

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	UCHAR Initialized;                                                      //0x4
	PVOID SsHandle;                                                         //0x8
	LIST_ENTRY InLoadOrderModuleList;                               //0x10
	LIST_ENTRY InMemoryOrderModuleList;                             //0x20
	LIST_ENTRY InInitializationOrderModuleList;                     //0x30
	PVOID EntryInProgress;                                                  //0x40
	UCHAR ShutdownInProgress;                                               //0x48
	PVOID ShutdownThreadId;                                                 //0x50
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
	PVOID EntryPoint;
	PVOID Reserved3;
	UNICODE_STRING FullDllName;
	BYTE Reserved4[8];
	PVOID Reserved5[3];
	union {
		ULONG CheckSum;
		PVOID Reserved6;
	};
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _REAL_PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[21];
	PPEB_LDR_DATA LoaderData;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	BYTE Reserved3[520];
	PVOID PostProcessInitRoutine;
	BYTE Reserved4[136];
	ULONG SessionId;
} REALPEB, * PREALPEB;

#endif