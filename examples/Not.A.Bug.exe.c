typedef unsigned char   undefined;

typedef unsigned long long    GUID;
typedef unsigned int    ImageBaseOffset32;
typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
typedef long long    longlong;
typedef unsigned long long    qword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef short    wchar_t;
typedef unsigned short    word;
typedef struct _s__RTTIClassHierarchyDescriptor _s__RTTIClassHierarchyDescriptor, *P_s__RTTIClassHierarchyDescriptor;

typedef struct _s__RTTIClassHierarchyDescriptor RTTIClassHierarchyDescriptor;

struct _s__RTTIClassHierarchyDescriptor {
    dword signature;
    dword attributes; // bit flags
    dword numBaseClasses; // number of base classes (i.e. rtti1Count)
    ImageBaseOffset32 pBaseClassArray; // ref to BaseClassArray (RTTI 2)
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct {
    dword OffsetToDirectory;
    dword DataIsDirectory;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion {
    dword OffsetToData;
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;
};

typedef struct _s__RTTIBaseClassDescriptor _s__RTTIBaseClassDescriptor, *P_s__RTTIBaseClassDescriptor;

typedef struct PMD PMD, *PPMD;

struct PMD {
    int mdisp;
    int pdisp;
    int vdisp;
};

struct _s__RTTIBaseClassDescriptor {
    ImageBaseOffset32 pTypeDescriptor; // ref to TypeDescriptor (RTTI 0) for class
    dword numContainedBases; // count of extended classes in BaseClassArray (RTTI 2)
    struct PMD where; // member displacement structure
    dword attributes; // bit flags
    ImageBaseOffset32 pClassHierarchyDescriptor; // ref to ClassHierarchyDescriptor (RTTI 3) for class
};

typedef struct _s__RTTIBaseClassDescriptor RTTIBaseClassDescriptor;

typedef struct _s__RTTICompleteObjectLocator _s__RTTICompleteObjectLocator, *P_s__RTTICompleteObjectLocator;

struct _s__RTTICompleteObjectLocator {
    dword signature;
    dword offset; // offset of vbtable within class
    dword cdOffset; // constructor displacement offset
    ImageBaseOffset32 pTypeDescriptor; // ref to TypeDescriptor (RTTI 0) for class
    ImageBaseOffset32 pClassDescriptor; // ref to ClassHierarchyDescriptor (RTTI 3)
};

typedef struct TypeDescriptor TypeDescriptor, *PTypeDescriptor;

struct TypeDescriptor {
    void * pVFTable;
    void * spare;
    char[0] name;
};

typedef struct _s__RTTICompleteObjectLocator RTTICompleteObjectLocator;

typedef ulonglong __uint64;

typedef struct _Fac_tidy_reg_t _Fac_tidy_reg_t, *P_Fac_tidy_reg_t;

struct _Fac_tidy_reg_t { // PlaceHolder Class Structure
};

typedef struct basic_streambuf<char,struct_std::char_traits<char>_> basic_streambuf<char,struct_std::char_traits<char>_>, *Pbasic_streambuf<char,struct_std::char_traits<char>_>;

struct basic_streambuf<char,struct_std::char_traits<char>_> { // PlaceHolder Class Structure
};

typedef struct ios_base ios_base, *Pios_base;

struct ios_base { // PlaceHolder Class Structure
};

typedef struct codecvt_base codecvt_base, *Pcodecvt_base;

struct codecvt_base { // PlaceHolder Class Structure
};

typedef struct basic_ostream<char,struct_std::char_traits<char>_> basic_ostream<char,struct_std::char_traits<char>_>, *Pbasic_ostream<char,struct_std::char_traits<char>_>;

struct basic_ostream<char,struct_std::char_traits<char>_> { // PlaceHolder Class Structure
};

typedef struct basic_ios<char,struct_std::char_traits<char>_> basic_ios<char,struct_std::char_traits<char>_>, *Pbasic_ios<char,struct_std::char_traits<char>_>;

struct basic_ios<char,struct_std::char_traits<char>_> { // PlaceHolder Class Structure
};

typedef struct codecvt<char,char,struct__Mbstatet> codecvt<char,char,struct__Mbstatet>, *Pcodecvt<char,char,struct__Mbstatet>;

struct codecvt<char,char,struct__Mbstatet> { // PlaceHolder Class Structure
};

typedef struct _Lockit _Lockit, *P_Lockit;

struct _Lockit { // PlaceHolder Class Structure
};

typedef struct id id, *Pid;

struct id { // PlaceHolder Class Structure
};

typedef long LONG;

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

typedef LONG (* PTOP_LEVEL_EXCEPTION_FILTER)(struct _EXCEPTION_POINTERS *);

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD * PEXCEPTION_RECORD;

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

typedef struct _CONTEXT * PCONTEXT;

typedef ulong DWORD;

typedef void * PVOID;

typedef ulonglong ULONG_PTR;

typedef ulonglong DWORD64;

typedef ushort WORD;

typedef union _union_52 _union_52, *P_union_52;

typedef struct _M128A _M128A, *P_M128A;

typedef struct _M128A M128A;

typedef struct _XSAVE_FORMAT _XSAVE_FORMAT, *P_XSAVE_FORMAT;

typedef struct _XSAVE_FORMAT XSAVE_FORMAT;

typedef XSAVE_FORMAT XMM_SAVE_AREA32;

typedef struct _struct_53 _struct_53, *P_struct_53;

typedef ulonglong ULONGLONG;

typedef longlong LONGLONG;

typedef uchar BYTE;

struct _M128A {
    ULONGLONG Low;
    LONGLONG High;
};

struct _XSAVE_FORMAT {
    WORD ControlWord;
    WORD StatusWord;
    BYTE TagWord;
    BYTE Reserved1;
    WORD ErrorOpcode;
    DWORD ErrorOffset;
    WORD ErrorSelector;
    WORD Reserved2;
    DWORD DataOffset;
    WORD DataSelector;
    WORD Reserved3;
    DWORD MxCsr;
    DWORD MxCsr_Mask;
    M128A FloatRegisters[8];
    M128A XmmRegisters[16];
    BYTE Reserved4[96];
};

struct _struct_53 {
    M128A Header[2];
    M128A Legacy[8];
    M128A Xmm0;
    M128A Xmm1;
    M128A Xmm2;
    M128A Xmm3;
    M128A Xmm4;
    M128A Xmm5;
    M128A Xmm6;
    M128A Xmm7;
    M128A Xmm8;
    M128A Xmm9;
    M128A Xmm10;
    M128A Xmm11;
    M128A Xmm12;
    M128A Xmm13;
    M128A Xmm14;
    M128A Xmm15;
};

union _union_52 {
    XMM_SAVE_AREA32 FltSave;
    struct _struct_53 s;
};

struct _CONTEXT {
    DWORD64 P1Home;
    DWORD64 P2Home;
    DWORD64 P3Home;
    DWORD64 P4Home;
    DWORD64 P5Home;
    DWORD64 P6Home;
    DWORD ContextFlags;
    DWORD MxCsr;
    WORD SegCs;
    WORD SegDs;
    WORD SegEs;
    WORD SegFs;
    WORD SegGs;
    WORD SegSs;
    DWORD EFlags;
    DWORD64 Dr0;
    DWORD64 Dr1;
    DWORD64 Dr2;
    DWORD64 Dr3;
    DWORD64 Dr6;
    DWORD64 Dr7;
    DWORD64 Rax;
    DWORD64 Rcx;
    DWORD64 Rdx;
    DWORD64 Rbx;
    DWORD64 Rsp;
    DWORD64 Rbp;
    DWORD64 Rsi;
    DWORD64 Rdi;
    DWORD64 R8;
    DWORD64 R9;
    DWORD64 R10;
    DWORD64 R11;
    DWORD64 R12;
    DWORD64 R13;
    DWORD64 R14;
    DWORD64 R15;
    DWORD64 Rip;
    union _union_52 u;
    M128A VectorRegister[26];
    DWORD64 VectorControl;
    DWORD64 DebugControl;
    DWORD64 LastBranchToRip;
    DWORD64 LastBranchFromRip;
    DWORD64 LastExceptionToRip;
    DWORD64 LastExceptionFromRip;
};

struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD * ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
};

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

typedef PTOP_LEVEL_EXCEPTION_FILTER LPTOP_LEVEL_EXCEPTION_FILTER;

typedef union _LARGE_INTEGER _LARGE_INTEGER, *P_LARGE_INTEGER;

typedef struct _struct_19 _struct_19, *P_struct_19;

typedef struct _struct_20 _struct_20, *P_struct_20;

struct _struct_20 {
    DWORD LowPart;
    LONG HighPart;
};

struct _struct_19 {
    DWORD LowPart;
    LONG HighPart;
};

union _LARGE_INTEGER {
    struct _struct_19 s;
    struct _struct_20 u;
    LONGLONG QuadPart;
};

typedef union _LARGE_INTEGER LARGE_INTEGER;

typedef struct _struct_314 _struct_314, *P_struct_314;

struct _struct_314 {
    ULONGLONG Depth:16;
    ULONGLONG Sequence:48;
    ULONGLONG HeaderType:1;
    ULONGLONG Init:1;
    ULONGLONG Reserved:2;
    ULONGLONG NextEntry:60;
};

typedef struct _struct_313 _struct_313, *P_struct_313;

struct _struct_313 {
    ULONGLONG Depth:16;
    ULONGLONG Sequence:9;
    ULONGLONG NextEntry:39;
    ULONGLONG HeaderType:1;
    ULONGLONG Init:1;
    ULONGLONG Reserved:59;
    ULONGLONG Region:3;
};

typedef struct _struct_312 _struct_312, *P_struct_312;

struct _struct_312 {
    ULONGLONG Alignment;
    ULONGLONG Region;
};

typedef struct _struct_315 _struct_315, *P_struct_315;

struct _struct_315 {
    ULONGLONG Depth:16;
    ULONGLONG Sequence:48;
    ULONGLONG HeaderType:1;
    ULONGLONG Reserved:3;
    ULONGLONG NextEntry:60;
};

typedef struct _RUNTIME_FUNCTION _RUNTIME_FUNCTION, *P_RUNTIME_FUNCTION;

struct _RUNTIME_FUNCTION {
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindData;
};

typedef struct _RUNTIME_FUNCTION * PRUNTIME_FUNCTION;

typedef enum _EXCEPTION_DISPOSITION {
    ExceptionContinueSearch=1,
    ExceptionNestedException=2,
    ExceptionCollidedUnwind=3,
    ExceptionContinueExecution=0
} _EXCEPTION_DISPOSITION;

typedef enum _EXCEPTION_DISPOSITION EXCEPTION_DISPOSITION;

typedef EXCEPTION_DISPOSITION (EXCEPTION_ROUTINE)(struct _EXCEPTION_RECORD *, PVOID, struct _CONTEXT *, PVOID);

typedef union _SLIST_HEADER _SLIST_HEADER, *P_SLIST_HEADER;

union _SLIST_HEADER {
    struct _struct_312 s;
    struct _struct_313 Header8;
    struct _struct_314 Header16;
    struct _struct_315 HeaderX64;
};

typedef wchar_t WCHAR;

typedef WCHAR * LPCWSTR;

typedef struct _M128A * PM128A;

typedef struct _UNWIND_HISTORY_TABLE_ENTRY _UNWIND_HISTORY_TABLE_ENTRY, *P_UNWIND_HISTORY_TABLE_ENTRY;

typedef struct _UNWIND_HISTORY_TABLE_ENTRY UNWIND_HISTORY_TABLE_ENTRY;

struct _UNWIND_HISTORY_TABLE_ENTRY {
    DWORD64 ImageBase;
    PRUNTIME_FUNCTION FunctionEntry;
};

typedef union _union_61 _union_61, *P_union_61;

typedef ulonglong * PDWORD64;

typedef struct _struct_62 _struct_62, *P_struct_62;

struct _struct_62 {
    PDWORD64 Rax;
    PDWORD64 Rcx;
    PDWORD64 Rdx;
    PDWORD64 Rbx;
    PDWORD64 Rsp;
    PDWORD64 Rbp;
    PDWORD64 Rsi;
    PDWORD64 Rdi;
    PDWORD64 R8;
    PDWORD64 R9;
    PDWORD64 R10;
    PDWORD64 R11;
    PDWORD64 R12;
    PDWORD64 R13;
    PDWORD64 R14;
    PDWORD64 R15;
};

union _union_61 {
    PDWORD64 IntegerContext[16];
    struct _struct_62 s;
};

typedef struct _UNWIND_HISTORY_TABLE _UNWIND_HISTORY_TABLE, *P_UNWIND_HISTORY_TABLE;

typedef struct _UNWIND_HISTORY_TABLE * PUNWIND_HISTORY_TABLE;

struct _UNWIND_HISTORY_TABLE {
    DWORD Count;
    BYTE LocalHint;
    BYTE GlobalHint;
    BYTE Search;
    BYTE Once;
    DWORD64 LowAddress;
    DWORD64 HighAddress;
    UNWIND_HISTORY_TABLE_ENTRY Entry[12];
};

typedef struct _struct_60 _struct_60, *P_struct_60;

struct _struct_60 {
    PM128A Xmm0;
    PM128A Xmm1;
    PM128A Xmm2;
    PM128A Xmm3;
    PM128A Xmm4;
    PM128A Xmm5;
    PM128A Xmm6;
    PM128A Xmm7;
    PM128A Xmm8;
    PM128A Xmm9;
    PM128A Xmm10;
    PM128A Xmm11;
    PM128A Xmm12;
    PM128A Xmm13;
    PM128A Xmm14;
    PM128A Xmm15;
};

typedef void * HANDLE;

typedef union _SLIST_HEADER * PSLIST_HEADER;

typedef union _union_59 _union_59, *P_union_59;

union _union_59 {
    PM128A FloatingContext[16];
    struct _struct_60 s;
};

typedef struct _KNONVOLATILE_CONTEXT_POINTERS _KNONVOLATILE_CONTEXT_POINTERS, *P_KNONVOLATILE_CONTEXT_POINTERS;

typedef struct _KNONVOLATILE_CONTEXT_POINTERS * PKNONVOLATILE_CONTEXT_POINTERS;

struct _KNONVOLATILE_CONTEXT_POINTERS {
    union _union_59 u;
    union _union_61 u2;
};

typedef EXCEPTION_ROUTINE * PEXCEPTION_ROUTINE;

typedef struct IMAGE_DOS_HEADER IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

struct IMAGE_DOS_HEADER {
    char e_magic[2]; // Magic number
    word e_cblp; // Bytes of last page
    word e_cp; // Pages in file
    word e_crlc; // Relocations
    word e_cparhdr; // Size of header in paragraphs
    word e_minalloc; // Minimum extra paragraphs needed
    word e_maxalloc; // Maximum extra paragraphs needed
    word e_ss; // Initial (relative) SS value
    word e_sp; // Initial SP value
    word e_csum; // Checksum
    word e_ip; // Initial IP value
    word e_cs; // Initial (relative) CS value
    word e_lfarlc; // File address of relocation table
    word e_ovno; // Overlay number
    word e_res[4][4]; // Reserved words
    word e_oemid; // OEM identifier (for e_oeminfo)
    word e_oeminfo; // OEM information; e_oemid specific
    word e_res2[10][10]; // Reserved words
    dword e_lfanew; // File address of new exe header
    byte e_program[64]; // Actual DOS program
};

typedef struct DotNetPdbInfo DotNetPdbInfo, *PDotNetPdbInfo;

struct DotNetPdbInfo {
    char signature[4];
    GUID guid;
    dword age;
    char pdbname[65];
};

typedef longlong fpos_t;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME * LPFILETIME;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ * HINSTANCE;

struct HINSTANCE__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef int BOOL;

typedef uint UINT;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct {
    dword NameOffset;
    dword NameIsString;
};

typedef struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY IMAGE_LOAD_CONFIG_CODE_INTEGRITY, *PIMAGE_LOAD_CONFIG_CODE_INTEGRITY;

struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY {
    word Flags;
    word Catalog;
    dword CatalogOffset;
    dword Reserved;
};

typedef struct IMAGE_DEBUG_DIRECTORY IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

struct IMAGE_DEBUG_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword Type;
    dword SizeOfData;
    dword AddressOfRawData;
    dword PointerToRawData;
};

typedef struct IMAGE_FILE_HEADER IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

struct IMAGE_FILE_HEADER {
    word Machine; // 34404
    word NumberOfSections;
    dword TimeDateStamp;
    dword PointerToSymbolTable;
    dword NumberOfSymbols;
    word SizeOfOptionalHeader;
    word Characteristics;
};

typedef struct IMAGE_LOAD_CONFIG_DIRECTORY64 IMAGE_LOAD_CONFIG_DIRECTORY64, *PIMAGE_LOAD_CONFIG_DIRECTORY64;

typedef enum IMAGE_GUARD_FLAGS {
    IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION=8192,
    IMAGE_GUARD_CF_INSTRUMENTED=256,
    IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION=32768,
    IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT=16384,
    IMAGE_GUARD_CFW_INSTRUMENTED=512,
    IMAGE_GUARD_RF_INSTRUMENTED=131072,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_4=1073741824,
    IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT=65536,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_2=536870912,
    IMAGE_GUARD_PROTECT_DELAYLOAD_IAT=4096,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_1=268435456,
    IMAGE_GUARD_SECURITY_COOKIE_UNUSED=2048,
    IMAGE_GUARD_RF_STRICT=524288,
    IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT=1024,
    IMAGE_GUARD_RF_ENABLE=262144,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_8=2147483648
} IMAGE_GUARD_FLAGS;

struct IMAGE_LOAD_CONFIG_DIRECTORY64 {
    dword Size;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword GlobalFlagsClear;
    dword GlobalFlagsSet;
    dword CriticalSectionDefaultTimeout;
    qword DeCommitFreeBlockThreshold;
    qword DeCommitTotalFreeThreshold;
    pointer64 LockPrefixTable;
    qword MaximumAllocationSize;
    qword VirtualMemoryThreshold;
    qword ProcessAffinityMask;
    dword ProcessHeapFlags;
    word CsdVersion;
    word DependentLoadFlags;
    pointer64 EditList;
    pointer64 SecurityCookie;
    pointer64 SEHandlerTable;
    qword SEHandlerCount;
    pointer64 GuardCFCCheckFunctionPointer;
    pointer64 GuardCFDispatchFunctionPointer;
    pointer64 GuardCFFunctionTable;
    qword GuardCFFunctionCount;
    enum IMAGE_GUARD_FLAGS GuardFlags;
    struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
    pointer64 GuardAddressTakenIatEntryTable;
    qword GuardAddressTakenIatEntryCount;
    pointer64 GuardLongJumpTargetTable;
    qword GuardLongJumpTargetCount;
    pointer64 DynamicValueRelocTable;
    pointer64 CHPEMetadataPointer;
    pointer64 GuardRFFailureRoutine;
    pointer64 GuardRFFailureRoutineFunctionPointer;
    dword DynamicValueRelocTableOffset;
    word DynamicValueRelocTableSection;
    word Reserved1;
    pointer64 GuardRFVerifyStackPointerFunctionPointer;
    dword HotPatchTableOffset;
    dword Reserved2;
    qword Reserved3;
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion;

union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion {
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;
    dword Name;
    word Id;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion NameUnion;
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion DirectoryUnion;
};

typedef struct IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY {
    ImageBaseOffset32 VirtualAddress;
    dword Size;
};

struct IMAGE_OPTIONAL_HEADER64 {
    word Magic;
    byte MajorLinkerVersion;
    byte MinorLinkerVersion;
    dword SizeOfCode;
    dword SizeOfInitializedData;
    dword SizeOfUninitializedData;
    ImageBaseOffset32 AddressOfEntryPoint;
    ImageBaseOffset32 BaseOfCode;
    pointer64 ImageBase;
    dword SectionAlignment;
    dword FileAlignment;
    word MajorOperatingSystemVersion;
    word MinorOperatingSystemVersion;
    word MajorImageVersion;
    word MinorImageVersion;
    word MajorSubsystemVersion;
    word MinorSubsystemVersion;
    dword Win32VersionValue;
    dword SizeOfImage;
    dword SizeOfHeaders;
    dword CheckSum;
    word Subsystem;
    word DllCharacteristics;
    qword SizeOfStackReserve;
    qword SizeOfStackCommit;
    qword SizeOfHeapReserve;
    qword SizeOfHeapCommit;
    dword LoaderFlags;
    dword NumberOfRvaAndSizes;
    struct IMAGE_DATA_DIRECTORY DataDirectory[16];
};

typedef struct IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef union Misc Misc, *PMisc;

typedef enum SectionFlags {
    IMAGE_SCN_ALIGN_2BYTES=2097152,
    IMAGE_SCN_ALIGN_128BYTES=8388608,
    IMAGE_SCN_LNK_INFO=512,
    IMAGE_SCN_ALIGN_4096BYTES=13631488,
    IMAGE_SCN_MEM_READ=1073741824,
    IMAGE_SCN_ALIGN_8BYTES=4194304,
    IMAGE_SCN_ALIGN_64BYTES=7340032,
    IMAGE_SCN_ALIGN_256BYTES=9437184,
    IMAGE_SCN_MEM_WRITE=2147483648,
    IMAGE_SCN_LNK_COMDAT=4096,
    IMAGE_SCN_MEM_16BIT=131072,
    IMAGE_SCN_ALIGN_8192BYTES=14680064,
    IMAGE_SCN_MEM_PURGEABLE=131072,
    IMAGE_SCN_GPREL=32768,
    IMAGE_SCN_MEM_EXECUTE=536870912,
    IMAGE_SCN_ALIGN_4BYTES=3145728,
    IMAGE_SCN_LNK_OTHER=256,
    IMAGE_SCN_MEM_PRELOAD=524288,
    IMAGE_SCN_ALIGN_1BYTES=1048576,
    IMAGE_SCN_MEM_NOT_PAGED=134217728,
    IMAGE_SCN_ALIGN_1024BYTES=11534336,
    IMAGE_SCN_RESERVED_0001=16,
    IMAGE_SCN_MEM_LOCKED=262144,
    IMAGE_SCN_ALIGN_512BYTES=10485760,
    IMAGE_SCN_CNT_INITIALIZED_DATA=64,
    IMAGE_SCN_ALIGN_32BYTES=6291456,
    IMAGE_SCN_MEM_DISCARDABLE=33554432,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA=128,
    IMAGE_SCN_ALIGN_2048BYTES=12582912,
    IMAGE_SCN_MEM_SHARED=268435456,
    IMAGE_SCN_CNT_CODE=32,
    IMAGE_SCN_LNK_REMOVE=2048,
    IMAGE_SCN_ALIGN_16BYTES=5242880,
    IMAGE_SCN_TYPE_NO_PAD=8,
    IMAGE_SCN_LNK_NRELOC_OVFL=16777216,
    IMAGE_SCN_RESERVED_0040=1024,
    IMAGE_SCN_MEM_NOT_CACHED=67108864
} SectionFlags;

union Misc {
    dword PhysicalAddress;
    dword VirtualSize;
};

struct IMAGE_SECTION_HEADER {
    char Name[8];
    union Misc Misc;
    ImageBaseOffset32 VirtualAddress;
    dword SizeOfRawData;
    dword PointerToRawData;
    dword PointerToRelocations;
    dword PointerToLinenumbers;
    word NumberOfRelocations;
    word NumberOfLinenumbers;
    enum SectionFlags Characteristics;
};

typedef struct IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

struct IMAGE_NT_HEADERS64 {
    char Signature[4];
    struct IMAGE_FILE_HEADER FileHeader;
    struct IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};

typedef struct IMAGE_RESOURCE_DATA_ENTRY IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

struct IMAGE_RESOURCE_DATA_ENTRY {
    dword OffsetToData;
    dword Size;
    dword CodePage;
    dword Reserved;
};

typedef struct IMAGE_RESOURCE_DIRECTORY IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

struct IMAGE_RESOURCE_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    word NumberOfNamedEntries;
    word NumberOfIdEntries;
};

typedef struct _iobuf _iobuf, *P_iobuf;

struct _iobuf {
    char * _ptr;
    int _cnt;
    char * _base;
    int _flag;
    int _file;
    int _charbuf;
    int _bufsiz;
    char * _tmpfname;
};

typedef struct _iobuf FILE;

typedef int PMFN;

typedef struct _s_ThrowInfo _s_ThrowInfo, *P_s_ThrowInfo;

struct _s_ThrowInfo {
    uint attributes;
    PMFN pmfnUnwind;
    int pForwardCompat;
    int pCatchableTypeArray;
};

typedef struct _s_ThrowInfo ThrowInfo;

typedef struct _Mbstatet _Mbstatet, *P_Mbstatet;

struct _Mbstatet { // PlaceHolder Structure
};

typedef struct _Facet_base _Facet_base, *P_Facet_base;

struct _Facet_base { // PlaceHolder Structure
};

typedef struct basic_istream<char,struct_std::char_traits<char>_> basic_istream<char,struct_std::char_traits<char>_>, *Pbasic_istream<char,struct_std::char_traits<char>_>;

struct basic_istream<char,struct_std::char_traits<char>_> { // PlaceHolder Structure
};

typedef struct locale locale, *Plocale;

struct locale { // PlaceHolder Structure
};

typedef struct _Locimp _Locimp, *P_Locimp;

struct _Locimp { // PlaceHolder Structure
};

typedef struct facet facet, *Pfacet;

struct facet { // PlaceHolder Structure
};

typedef int (* _onexit_t)(void);

typedef int errno_t;

typedef ulonglong size_t;




undefined ** FUN_140001010(undefined **param_1,longlong param_2)

{
  *param_1 = (undefined *)std::exception::vftable;
  *(undefined (*) [16])(param_1 + 1) = ZEXT816(0);
  __std_exception_copy(param_2 + 8);
  return param_1;
}



char * FUN_140001050(longlong param_1)

{
  char *pcVar1;
  
  pcVar1 = "Unknown exception";
  if (*(char **)(param_1 + 8) != (char *)0x0) {
    pcVar1 = *(char **)(param_1 + 8);
  }
  return pcVar1;
}



undefined ** FUN_140001070(undefined **param_1,ulonglong param_2)

{
  *param_1 = (undefined *)std::exception::vftable;
  __std_exception_destroy(param_1 + 1);
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



undefined ** FUN_1400010e0(undefined **param_1)

{
  param_1[2] = (undefined *)0x0;
  param_1[1] = "bad array new length";
  *param_1 = (undefined *)std::bad_array_new_length::vftable;
  return param_1;
}



void FUN_140001110(void)

{
  undefined *local_28 [5];
  
  FUN_1400010e0(local_28);
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_28,(ThrowInfo *)&DAT_140007fd8);
}



undefined ** FUN_140001130(undefined **param_1,longlong param_2)

{
  *param_1 = (undefined *)std::exception::vftable;
  *(undefined (*) [16])(param_1 + 1) = ZEXT816(0);
  __std_exception_copy(param_2 + 8);
  *param_1 = (undefined *)std::bad_array_new_length::vftable;
  return param_1;
}



undefined ** FUN_140001170(undefined **param_1,longlong param_2)

{
  *param_1 = (undefined *)std::exception::vftable;
  *(undefined (*) [16])(param_1 + 1) = ZEXT816(0);
  __std_exception_copy(param_2 + 8);
  *param_1 = (undefined *)std::bad_alloc::vftable;
  return param_1;
}



undefined ** FUN_1400011b0(undefined **param_1)

{
  param_1[2] = (undefined *)0x0;
  param_1[1] = "bad cast";
  *param_1 = (undefined *)std::bad_cast::vftable;
  return param_1;
}



void FUN_1400011e0(void)

{
  undefined *local_28 [5];
  
  FUN_1400011b0(local_28);
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_28,(ThrowInfo *)&DAT_140007f18);
}



undefined ** FUN_140001200(undefined **param_1,longlong param_2)

{
  *param_1 = (undefined *)std::exception::vftable;
  *(undefined (*) [16])(param_1 + 1) = ZEXT816(0);
  __std_exception_copy(param_2 + 8);
  *param_1 = (undefined *)std::bad_cast::vftable;
  return param_1;
}



void FUN_140001240(longlong param_1)

{
  code **ppcVar1;
  
  if (*(longlong **)(param_1 + 8) != (longlong *)0x0) {
    ppcVar1 = (code **)(**(code **)(**(longlong **)(param_1 + 8) + 0x10))();
    if (ppcVar1 != (code **)0x0) {
                    // WARNING: Could not recover jumptable at 0x000140001267. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)*ppcVar1)(ppcVar1,1);
      return;
    }
  }
  return;
}



void FUN_140001270(longlong **param_1,DWORD param_2)

{
  code *pcVar1;
  longlong **pplVar2;
  longlong *_Memory;
  longlong *plVar3;
  undefined auStack56 [32];
  longlong **local_18;
  ulonglong local_10;
  
  local_10 = DAT_14000a010 ^ (ulonglong)auStack56;
  plVar3 = (longlong *)0x0;
  local_18 = param_1;
  if (param_1[2] != (longlong *)0x0) {
    do {
      pplVar2 = param_1;
      if ((longlong *)0xf < param_1[3]) {
        pplVar2 = (longlong **)*param_1;
      }
      FUN_1400039c0((longlong *)cout_exref,*(char *)((longlong)plVar3 + (longlong)pplVar2));
      Sleep(param_2);
      plVar3 = (longlong *)(ulonglong)((int)plVar3 + 1);
    } while (plVar3 < param_1[2]);
  }
  if ((longlong *)0xf < param_1[3]) {
    plVar3 = *param_1;
    _Memory = plVar3;
    if ((0xfff < (longlong)param_1[3] + 1U) &&
       (_Memory = (longlong *)plVar3[-1],
       0x1f < (ulonglong)((longlong)plVar3 + (-8 - (longlong)_Memory)))) {
      _invalid_parameter_noinfo_noreturn();
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
    free(_Memory);
  }
  param_1[2] = (longlong *)0x0;
  param_1[3] = (longlong *)0xf;
  *(undefined *)param_1 = 0;
  FUN_1400047b0(local_10 ^ (ulonglong)auStack56);
  return;
}



void FUN_140001340(longlong **param_1)

{
  longlong *plVar1;
  code *pcVar2;
  longlong *_Memory;
  longlong **pplVar3;
  undefined auStack56 [32];
  longlong **local_18;
  ulonglong local_10;
  
  local_10 = DAT_14000a010 ^ (ulonglong)auStack56;
  pplVar3 = param_1;
  if ((longlong *)0xf < param_1[3]) {
    pplVar3 = (longlong **)*param_1;
  }
  local_18 = param_1;
  FUN_140004410((longlong *)cout_exref,(char *)pplVar3,(ulonglong)param_1[2]);
  if ((longlong *)0xf < param_1[3]) {
    plVar1 = *param_1;
    _Memory = plVar1;
    if ((0xfff < (longlong)param_1[3] + 1U) &&
       (_Memory = (longlong *)plVar1[-1],
       0x1f < (ulonglong)((longlong)plVar1 + (-8 - (longlong)_Memory)))) {
      _invalid_parameter_noinfo_noreturn();
      pcVar2 = (code *)swi(3);
      (*pcVar2)();
      return;
    }
    free(_Memory);
  }
  param_1[2] = (longlong *)0x0;
  param_1[3] = (longlong *)0xf;
  *(undefined *)param_1 = 0;
  FUN_1400047b0(local_10 ^ (ulonglong)auStack56);
  return;
}



void FUN_1400013e0(void)

{
  code *pcVar1;
  void *pvVar2;
  void *_Memory;
  undefined auStack88 [32];
  undefined local_38;
  undefined7 uStack55;
  undefined8 local_28;
  ulonglong local_20;
  ulonglong local_18;
  
  local_18 = DAT_14000a010 ^ (ulonglong)auStack88;
  local_28 = 0;
  local_20 = 0xf;
  local_38 = 0;
  FUN_140004220((longlong *)cin_exref,(void **)&local_38);
  if (0xf < local_20) {
    pvVar2 = (void *)CONCAT71(uStack55,local_38);
    _Memory = pvVar2;
    if ((0xfff < local_20 + 1) &&
       (_Memory = *(void **)((longlong)pvVar2 + -8),
       0x1f < (ulonglong)((longlong)pvVar2 + (-8 - (longlong)_Memory)))) {
      _invalid_parameter_noinfo_noreturn();
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
    free(_Memory);
  }
  FUN_1400047b0(local_18 ^ (ulonglong)auStack88);
  return;
}



// WARNING: Exceeded maximum restarts with more pending

void FUN_140001470(longlong *param_1)

{
  longlong *plVar1;
  undefined **this;
  longlong lVar2;
  longlong *plVar3;
  
  plVar1 = param_1 + 0x15;
  *(undefined ***)((longlong)*(int *)(*param_1 + 4) + -0xa8 + (longlong)plVar1) =
       std::basic_ofstream<char,struct_std::char_traits<char>_>::vftable;
  *(int *)((longlong)*(int *)(*param_1 + 4) + -0xac + (longlong)plVar1) =
       *(int *)(*param_1 + 4) + -0xa8;
  this = (undefined **)(param_1 + 1);
  *this = (undefined *)std::basic_filebuf<char,struct_std::char_traits<char>_>::vftable;
  if ((param_1[0x11] != 0) && (*(longlong **)param_1[4] == param_1 + 0xf)) {
    lVar2 = param_1[0x13];
    plVar3 = (longlong *)param_1[0x12];
    *(longlong **)param_1[4] = plVar3;
    *(longlong **)param_1[8] = plVar3;
    *(int *)param_1[0xb] = (int)lVar2 - (int)plVar3;
  }
  if (*(char *)((longlong)param_1 + 0x84) != '\0') {
    FUN_140003630((longlong *)this);
  }
  std::basic_streambuf<char,struct_std::char_traits<char>_>::
  _basic_streambuf_char_struct_std__char_traits_char___
            ((basic_streambuf_char_struct_std__char_traits_char___ *)this);
  std::basic_ostream<char,struct_std::char_traits<char>_>::
  _basic_ostream_char_struct_std__char_traits_char___
            ((basic_ostream_char_struct_std__char_traits_char___ *)(param_1 + 2));
                    // WARNING: Could not recover jumptable at 0x00014000152f. Too many branches
                    // WARNING: Treating indirect jump as call
  std::basic_ios<char,struct_std::char_traits<char>_>::
  _basic_ios_char_struct_std__char_traits_char___(plVar1);
  return;
}



void FUN_140001540(longlong **param_1)

{
  code *pcVar1;
  void *pvVar2;
  uint *puVar3;
  uint **ppuVar4;
  longlong *plVar5;
  void *pvVar6;
  longlong *_Memory;
  longlong **pplVar7;
  uint *puVar8;
  undefined auStack408 [32];
  undefined4 local_178;
  uint local_170;
  undefined4 uStack364;
  undefined4 uStack360;
  undefined4 uStack356;
  uint *local_160;
  uint *puStack344;
  undefined local_150;
  undefined7 uStack335;
  undefined8 local_140;
  ulonglong local_138;
  longlong **local_130;
  longlong local_128;
  longlong local_120 [33];
  ulonglong local_18;
  
  local_18 = DAT_14000a010 ^ (ulonglong)auStack408;
  local_178 = 0;
  local_130 = param_1;
  memset(&local_128,0,0x108);
  FUN_140003300(&local_128);
  FUN_140003170(&local_128);
  local_140 = 0;
  local_138 = 0xf;
  local_150 = 0;
  local_178 = 1;
  if ((longlong *)0xf < param_1[2] + 2) {
    FUN_1400045d0((void **)&local_150,(ulonglong)(param_1[2] + 2));
  }
  local_140 = 0;
  FUN_140003810((void **)&local_150,"The Password is ",(void *)0x10);
  pplVar7 = param_1;
  if ((longlong *)0xf < param_1[3]) {
    pplVar7 = (longlong **)*param_1;
  }
  FUN_140003810((void **)&local_150,pplVar7,param_1[2]);
  ppuVar4 = (uint **)FUN_140003810((void **)&local_150,&DAT_14000664c,(void *)0x1);
  local_170 = *(uint *)ppuVar4;
  uStack364 = *(undefined4 *)((longlong)ppuVar4 + 4);
  puVar3 = *ppuVar4;
  uStack360 = *(undefined4 *)(ppuVar4 + 1);
  uStack356 = *(undefined4 *)((longlong)ppuVar4 + 0xc);
  local_160 = ppuVar4[2];
  puStack344 = ppuVar4[3];
  ppuVar4[2] = (uint *)0x0;
  ppuVar4[3] = (uint *)0xf;
  *(undefined *)ppuVar4 = 0;
  local_178 = 3;
  puVar8 = &local_170;
  if ((uint *)0xf < puStack344) {
    puVar8 = puVar3;
  }
  FUN_140004410(&local_128,(char *)puVar8,(ulonglong)local_160);
  if ((uint *)0xf < puStack344) {
    pvVar2 = (void *)CONCAT44(uStack364,local_170);
    pvVar6 = pvVar2;
    if (((char *)0xfff < (char *)((longlong)puStack344 + 1)) &&
       (pvVar6 = *(void **)((longlong)pvVar2 + -8),
       0x1f < (ulonglong)((longlong)pvVar2 + (-8 - (longlong)pvVar6)))) {
      _invalid_parameter_noinfo_noreturn();
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
    free(pvVar6);
  }
  local_160 = (uint *)0x0;
  puStack344 = (uint *)0xf;
  local_170 = local_170 & 0xffffff00;
  if (0xf < local_138) {
    pvVar2 = (void *)CONCAT71(uStack335,local_150);
    pvVar6 = pvVar2;
    if ((0xfff < local_138 + 1) &&
       (pvVar6 = *(void **)((longlong)pvVar2 + -8),
       0x1f < (ulonglong)((longlong)pvVar2 + (-8 - (longlong)pvVar6)))) {
      _invalid_parameter_noinfo_noreturn();
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
    free(pvVar6);
  }
  plVar5 = FUN_140003630(local_120);
  if (plVar5 == (longlong *)0x0) {
    std::basic_ios<char,struct_std::char_traits<char>_>::setstate
              ((basic_ios_char_struct_std__char_traits_char___ *)
               ((longlong)local_120 + (longlong)*(int *)(local_128 + 4) + -8),2,false);
  }
  FUN_140001470(&local_128);
  if ((longlong *)0xf < param_1[3]) {
    plVar5 = *param_1;
    _Memory = plVar5;
    if ((0xfff < (longlong)param_1[3] + 1U) &&
       (_Memory = (longlong *)plVar5[-1],
       0x1f < (ulonglong)((longlong)plVar5 + (-8 - (longlong)_Memory)))) {
      _invalid_parameter_noinfo_noreturn();
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
    free(_Memory);
  }
  param_1[2] = (longlong *)0x0;
  param_1[3] = (longlong *)0xf;
  *(undefined *)param_1 = 0;
  FUN_1400047b0(local_18 ^ (ulonglong)auStack408);
  return;
}



void FUN_1400017c0(void)

{
  longlong *plVar1;
  int iVar2;
  longlong lVar3;
  undefined local_28;
  undefined8 local_18;
  undefined8 local_10;
  
  system("color B1");
  iVar2 = 0;
  local_10 = 0xf;
  local_18 = 0;
  local_28 = 0;
  FUN_1400036b0((longlong **)&local_28,"Hello World!\n",(longlong *)0xd);
  FUN_140001270((longlong **)&local_28,100);
  local_18 = 0;
  local_10 = 0xf;
  local_28 = 0;
  FUN_1400036b0((longlong **)&local_28,"Wanna install the best game of all time?",(longlong *)0x28);
  FUN_140001270((longlong **)&local_28,100);
  FUN_1400013e0();
  local_18 = 0;
  local_10 = 0xf;
  local_28 = 0;
  FUN_1400036b0((longlong **)&local_28,"Don\'t care about your answer i install it.",
                (longlong *)0x2a);
  FUN_140001270((longlong **)&local_28,10);
  Sleep(0x5dc);
  system("CLS");
  do {
    plVar1 = (longlong *)
             std::basic_ostream<char,struct_std::char_traits<char>_>::operator__
                       ((basic_ostream_char_struct_std__char_traits_char___ *)cout_exref,iVar2);
    FUN_140003b80(plVar1,"% Loading");
    Sleep(10);
    system("CLS");
    iVar2 = iVar2 + 1;
  } while (iVar2 < 100);
  system("color C1");
  local_18 = 0;
  local_10 = 0xf;
  local_28 = 0;
  FUN_1400036b0((longlong **)&local_28,"99% Loading\n",(longlong *)0xc);
  FUN_140001340((longlong **)&local_28);
  lVar3 = 0x1e;
  do {
    system("color B1");
    Sleep(100);
    system("color C1");
    Sleep(100);
    local_18 = 0;
    local_10 = 0xf;
    local_28 = 0;
    FUN_1400036b0((longlong **)&local_28,"[FATAL ERROR] BUG DETECTED IN THE INSTALLATION ABORT! \n",
                  (longlong *)0x37);
    FUN_140001340((longlong **)&local_28);
    lVar3 = lVar3 + -1;
  } while (lVar3 != 0);
  local_18 = 0;
  local_10 = 0xf;
  local_28 = 0;
  FUN_1400036b0((longlong **)&local_28,"Reebooting...",(longlong *)0xd);
  FUN_140001340((longlong **)&local_28);
  Sleep(2000);
  system("color 01");
                    // WARNING: Could not recover jumptable at 0x0001400019d0. Too many branches
                    // WARNING: Treating indirect jump as call
  system("CLS");
  return;
}



// WARNING: Type propagation algorithm not settling

void FUN_1400019e0(void)

{
  ulonglong uVar1;
  code *pcVar2;
  int iVar3;
  void **ppvVar4;
  longlong *plVar5;
  void *pvVar6;
  longlong **pplVar7;
  undefined *puVar8;
  undefined *puVar9;
  char *pcVar10;
  void *pvVar11;
  ulonglong uVar12;
  longlong **pplVar13;
  longlong *plVar14;
  uint uVar15;
  ulonglong uVar16;
  undefined auStack520 [32];
  undefined4 local_1e8;
  longlong *local_1e0;
  undefined4 uStack472;
  undefined4 uStack468;
  void *local_1d0;
  ulonglong local_1c8;
  uint local_1c0;
  uint uStack444;
  undefined4 uStack440;
  undefined4 uStack436;
  void *local_1b0;
  void *pvStack424;
  undefined8 local_190;
  void *local_180;
  ulonglong local_178;
  undefined8 local_170;
  void *local_160;
  ulonglong local_158;
  longlong local_148;
  longlong local_140 [33];
  ulonglong local_38;
  
  local_38 = DAT_14000a010 ^ (ulonglong)auStack520;
  plVar14 = (longlong *)0x0;
  local_1e8 = 0;
  local_180 = (void *)0x0;
  local_178 = 0xf;
  local_190._0_1_ = 0;
  system("color 07");
  Sleep(5000);
  local_1d0 = (void *)0x0;
  local_1c8 = 0xf;
  local_1e0 = (longlong *)((ulonglong)local_1e0 & 0xffffffffffffff00);
  FUN_1400036b0(&local_1e0,"Oh hello there! \n",(longlong *)0x11);
  FUN_140001270(&local_1e0,100);
  local_1d0 = (void *)0x0;
  local_1c8 = 0xf;
  local_1e0 = (longlong *)((ulonglong)local_1e0 & 0xffffffffffffff00);
  FUN_1400036b0(&local_1e0,"Do you know where we are?\n",(longlong *)0x1a);
  FUN_140001270(&local_1e0,100);
  FUN_140004220((longlong *)cin_exref,(void **)&local_190);
  pvVar11 = local_180;
  local_1d0 = (void *)0x0;
  local_1c8 = 0xf;
  local_1e0 = (longlong *)((ulonglong)local_1e0 & 0xffffffffffffff00);
  local_1e8 = 1;
  if (0xf < (longlong)local_180 + 10U) {
    FUN_1400045d0(&local_1e0,(longlong)local_180 + 10U);
  }
  local_1d0 = (void *)0x0;
  FUN_140003810(&local_1e0,"We are in ",(void *)0xa);
  puVar8 = (undefined *)&local_190;
  if (0xf < local_178) {
    puVar8 = (undefined *)CONCAT71(local_190._1_7_,(undefined)local_190);
  }
  FUN_140003810(&local_1e0,puVar8,pvVar11);
  ppvVar4 = FUN_140003810(&local_1e0,&DAT_14000671c,(void *)0x3);
  local_1c0 = *(uint *)ppvVar4;
  uStack444 = *(uint *)((longlong)ppvVar4 + 4);
  uStack440 = *(undefined4 *)(ppvVar4 + 1);
  uStack436 = *(undefined4 *)((longlong)ppvVar4 + 0xc);
  local_1b0 = ppvVar4[2];
  pvStack424 = ppvVar4[3];
  ppvVar4[2] = (void *)0x0;
  ppvVar4[3] = (void *)0xf;
  *(undefined *)ppvVar4 = 0;
  local_1e8 = 3;
  FUN_140001270((longlong **)&local_1c0,100);
  if (0xf < local_1c8) {
    plVar5 = local_1e0;
    if ((0xfff < local_1c8 + 1) &&
       (plVar5 = (longlong *)local_1e0[-1],
       0x1f < (ulonglong)((longlong)local_1e0 + (-8 - (longlong)plVar5)))) {
      _invalid_parameter_noinfo_noreturn();
      pcVar2 = (code *)swi(3);
      (*pcVar2)();
      return;
    }
    free(plVar5);
  }
  Sleep(500);
  local_1b0 = (void *)0x0;
  pvStack424 = (void *)0xf;
  local_1c0 = local_1c0 & 0xffffff00;
  FUN_1400036b0((longlong **)&local_1c0,"What is wrong with you ???\n",(longlong *)0x1b);
  FUN_140001270((longlong **)&local_1c0,10);
  local_1b0 = (void *)0x0;
  pvStack424 = (void *)0xf;
  local_1c0 = local_1c0 & 0xffffff00;
  FUN_1400036b0((longlong **)&local_1c0,"I\'M not a BUG YOU DUMBASS\n",(longlong *)0x1a);
  FUN_140001270((longlong **)&local_1c0,10);
  local_1b0 = (void *)0x0;
  pvStack424 = (void *)0xf;
  local_1c0 = local_1c0 & 0xffffff00;
  FUN_1400036b0((longlong **)&local_1c0,&DAT_14000676c,(longlong *)0x4);
  FUN_140001270((longlong **)&local_1c0,1000);
  Sleep(500);
  local_1b0 = (void *)0x0;
  pvStack424 = (void *)0xf;
  local_1c0 = local_1c0 & 0xffffff00;
  FUN_1400036b0((longlong **)&local_1c0,"Oh you didn\'t said that...\n",(longlong *)0x1b);
  FUN_140001270((longlong **)&local_1c0,100);
  Sleep(500);
  local_1b0 = (void *)0x0;
  pvStack424 = (void *)0xf;
  local_1c0 = local_1c0 & 0xffffff00;
  FUN_1400036b0((longlong **)&local_1c0,"I\'m afraid of bugs, what if your one of them?\n",
                (longlong *)0x2e);
  FUN_140001270((longlong **)&local_1c0,100);
  Sleep(500);
  local_1b0 = (void *)0x0;
  pvStack424 = (void *)0xf;
  local_1c0 = local_1c0 & 0xffffff00;
  FUN_1400036b0((longlong **)&local_1c0,"I need to test you before we continue to talk\n",
                (longlong *)0x2e);
  FUN_140001270((longlong **)&local_1c0,100);
  Sleep(500);
  local_1b0 = (void *)0x0;
  pvStack424 = (void *)0xf;
  local_1c0 = local_1c0 & 0xffffff00;
  FUN_1400036b0((longlong **)&local_1c0,"I have hide a secret password in my folder.\n",
                (longlong *)0x2c);
  FUN_140001270((longlong **)&local_1c0,100);
  local_1b0 = (void *)0x0;
  pvStack424 = (void *)0xf;
  local_1c0 = local_1c0 & 0xffffff00;
  FUN_1400036b0((longlong **)&local_1c0,"A bug would never find it ;) :\n",(longlong *)0x1f);
  FUN_140001270((longlong **)&local_1c0,100);
  local_1b0 = (void *)0x0;
  pvStack424 = (void *)0xf;
  local_1c0 = local_1c0 & 0xffffff00;
  FUN_1400036b0((longlong **)&local_1c0,"Enter Password:\n",(longlong *)0x10);
  FUN_140001340((longlong **)&local_1c0);
  iVar3 = _stat64i32("NO_PASSWORD_HERE");
  if ((iVar3 != 0) || ((uStack444 & 0x40000000) == 0)) {
    system("mkdir  NO_PASSWORD_HERE");
  }
  memset(&local_148,0,0x108);
  FUN_140003300(&local_148);
  FUN_140003170(&local_148);
  FUN_140003b80(&local_148,"ow lol u juici bug , your not gonna get the password hehe!");
  plVar5 = FUN_140003630(local_140);
  if (plVar5 == (longlong *)0x0) {
    std::basic_ios<char,struct_std::char_traits<char>_>::setstate
              ((basic_ios_char_struct_std__char_traits_char___ *)
               ((longlong)local_140 + (longlong)*(int *)(local_148 + 4) + -8),2,false);
  }
  FUN_140001470(&local_148);
  FUN_140004220((longlong *)cin_exref,(void **)&local_190);
  FUN_140003d50((void **)&local_170,&local_190);
  uVar12 = local_178;
  pvVar11 = local_180;
  local_1d0 = (void *)0x0;
  local_1c8 = 0;
  pplVar13 = (longlong **)CONCAT71(local_190._1_7_,(undefined)local_190);
  pplVar7 = (longlong **)&local_190;
  if (0xf < local_178) {
    pplVar7 = pplVar13;
  }
  if (local_180 < (void *)0x10) {
    local_1e0 = *pplVar7;
    uStack472 = *(undefined4 *)(pplVar7 + 1);
    uStack468 = *(undefined4 *)((longlong)pplVar7 + 0xc);
    uVar16 = 0xf;
  }
  else {
    uVar16 = (ulonglong)local_180 | 0xf;
    if (0x7fffffffffffffff < uVar16) {
      uVar16 = 0x7fffffffffffffff;
    }
    uVar1 = uVar16 + 1;
    if (uVar1 < 0x1000) {
      plVar5 = plVar14;
      if (uVar1 != 0) {
        plVar5 = (longlong *)operator_new(uVar1);
      }
    }
    else {
      if (uVar16 + 0x28 <= uVar1) {
        FUN_140001110();
        pcVar2 = (code *)swi(3);
        (*pcVar2)();
        return;
      }
      pvVar6 = operator_new(uVar16 + 0x28);
      if (pvVar6 == (void *)0x0) {
        _invalid_parameter_noinfo_noreturn();
        pcVar2 = (code *)swi(3);
        (*pcVar2)();
        return;
      }
      plVar5 = (longlong *)((longlong)pvVar6 + 0x27U & 0xffffffffffffffe0);
      plVar5[-1] = (longlong)pvVar6;
    }
    local_1e0 = plVar5;
    memcpy(plVar5,pplVar7,(longlong)pvVar11 + 1);
  }
  local_1d0 = pvVar11;
  local_1c8 = uVar16;
  FUN_140001540(&local_1e0);
  while( true ) {
    uVar16 = local_158;
    puVar8 = (undefined *)CONCAT71(local_170._1_7_,(undefined)local_170);
    puVar9 = (undefined *)&local_170;
    if (0xf < local_158) {
      puVar9 = puVar8;
    }
    pplVar7 = (longlong **)&local_190;
    if (0xf < uVar12) {
      pplVar7 = pplVar13;
    }
    if ((pvVar11 == local_160) && (iVar3 = memcmp(pplVar7,puVar9,(size_t)pvVar11), iVar3 == 0))
    break;
    uVar15 = (int)plVar14 + 1;
    plVar14 = (longlong *)(ulonglong)uVar15;
    local_1b0 = (void *)0x0;
    pvStack424 = (void *)0xf;
    local_1c0 = local_1c0 & 0xffffff00;
    if ((int)uVar15 < 6) {
      plVar5 = (longlong *)0x1e;
      pcVar10 = "WRONG PASSWORD try again ;) :\n";
    }
    else {
      plVar5 = (longlong *)0x3f;
      pcVar10 = "WRONG PASSWORD maybe look inside gta6.txt *cough* *cough* ;) :\n";
    }
    FUN_1400036b0((longlong **)&local_1c0,pcVar10,plVar5);
    FUN_140001270((longlong **)&local_1c0,100);
    FUN_140004220((longlong *)cin_exref,(void **)&local_190);
    pplVar13 = (longlong **)CONCAT71(local_190._1_7_,(undefined)local_190);
    pvVar11 = local_180;
    uVar12 = local_178;
  }
  if (0xf < uVar16) {
    puVar9 = puVar8;
    if ((0xfff < uVar16 + 1) &&
       (puVar9 = *(undefined **)(puVar8 + 0xfffffffffffffff8),
       0x1f < puVar8 + (-8 - (longlong)puVar9))) {
      _invalid_parameter_noinfo_noreturn();
      pcVar2 = (code *)swi(3);
      (*pcVar2)();
      return;
    }
    free(puVar9);
  }
  local_160 = (void *)0x0;
  local_158 = 0xf;
  local_170._0_1_ = 0;
  if (0xf < uVar12) {
    pplVar7 = pplVar13;
    if ((0xfff < uVar12 + 1) &&
       (pplVar7 = (longlong **)pplVar13[-1],
       0x1f < (ulonglong)((longlong)pplVar13 + (-8 - (longlong)pplVar7)))) {
      _invalid_parameter_noinfo_noreturn();
      pcVar2 = (code *)swi(3);
      (*pcVar2)();
      return;
    }
    free(pplVar7);
  }
  FUN_1400047b0(local_38 ^ (ulonglong)auStack520);
  return;
}



void FUN_140002100(void)

{
  code *pcVar1;
  void *pvVar2;
  ULONGLONG UVar3;
  void *_Memory;
  longlong lVar4;
  double dVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  undefined auStack152 [32];
  undefined local_78;
  undefined8 local_68;
  undefined8 local_60;
  undefined local_50;
  undefined7 uStack79;
  undefined8 local_40;
  ulonglong local_38;
  ulonglong local_30;
  
  local_30 = DAT_14000a010 ^ (ulonglong)auStack152;
  system("CLS");
  Sleep(2000);
  local_68 = 0;
  local_60 = 0xf;
  local_78 = 0;
  FUN_1400036b0((longlong **)&local_78,"Ok maybe your ",(longlong *)0xe);
  FUN_140001270((longlong **)&local_78,100);
  local_68 = 0;
  local_60 = 0xf;
  local_78 = 0;
  FUN_1400036b0((longlong **)&local_78,"a good bug.\n",(longlong *)0xc);
  lVar4 = 0x32;
  FUN_140001270((longlong **)&local_78,0x32);
  Sleep(1000);
  local_68 = 0;
  local_60 = 0xf;
  local_78 = 0;
  FUN_1400036b0((longlong **)&local_78,"i will destroy you...\n",(longlong *)0x16);
  FUN_140001270((longlong **)&local_78,100);
  system("color a");
  UVar3 = GetTickCount64();
  if ((longlong)UVar3 < 0) {
    dVar5 = (double)(UVar3 >> 1 | (ulonglong)((uint)UVar3 & 1));
    dVar5 = dVar5 + dVar5;
    uVar6 = SUB84(dVar5,0);
    uVar7 = (undefined4)((ulonglong)dVar5 >> 0x20);
  }
  else {
    uVar6 = SUB84((double)UVar3,0);
    uVar7 = (undefined4)((ulonglong)(double)UVar3 >> 0x20);
  }
  UVar3 = GetTickCount64();
  if ((longlong)UVar3 < 0) {
    dVar5 = (double)(UVar3 >> 1 | (ulonglong)((uint)UVar3 & 1));
    dVar5 = dVar5 + dVar5;
  }
  else {
    dVar5 = (double)UVar3;
  }
  uVar8 = 0;
  uVar9 = 0x40c38800;
  if (dVar5 - (double)CONCAT44(uVar7,uVar6) < 10000.0) {
    do {
      system("dir/s");
      UVar3 = GetTickCount64();
      if ((longlong)UVar3 < 0) {
        dVar5 = (double)(UVar3 >> 1 | (ulonglong)((uint)UVar3 & 1));
        dVar5 = dVar5 + dVar5;
      }
      else {
        dVar5 = (double)UVar3;
      }
      dVar5 = dVar5 - (double)CONCAT44(uVar7,uVar6);
    } while (dVar5 <= (double)CONCAT44(uVar9,uVar8) && (double)CONCAT44(uVar9,uVar8) != dVar5);
  }
  system("CLS");
  system("color 07");
  local_68 = 0;
  local_60 = 0xf;
  local_78 = 0;
  FUN_1400036b0((longlong **)&local_78,"HOW DO YOU SURVIVE DIR/S ????\n",(longlong *)0x1e);
  FUN_140001270((longlong **)&local_78,0x32);
  Sleep(1000);
  local_68 = 0;
  local_60 = 0xf;
  local_78 = 0;
  FUN_1400036b0((longlong **)&local_78,"And WHAT are you doing with this???",(longlong *)0x23);
  FUN_140001270((longlong **)&local_78,0x32);
  Sleep(500);
  do {
    system("start");
    lVar4 = lVar4 + -1;
  } while (lVar4 != 0);
  local_68 = 0;
  local_60 = 0xf;
  local_78 = 0;
  FUN_1400036b0((longlong **)&local_78,&DAT_140006954,(longlong *)0x4);
  FUN_140001340((longlong **)&local_78);
  local_40 = 0;
  local_38 = 0xf;
  local_50 = 0;
  FUN_140004220((longlong *)cin_exref,(void **)&local_50);
  local_68 = 0;
  local_60 = 0xf;
  local_78 = 0;
  FUN_1400036b0((longlong **)&local_78,"oh your still there...\n",(longlong *)0x17);
  FUN_140001270((longlong **)&local_78,100);
  local_68 = 0;
  local_60 = 0xf;
  local_78 = 0;
  FUN_1400036b0((longlong **)&local_78,"You know i\'m not a bug...\n",(longlong *)0x1a);
  FUN_140001270((longlong **)&local_78,100);
  local_68 = 0;
  local_60 = 0xf;
  local_78 = 0;
  FUN_1400036b0((longlong **)&local_78,"i\'m a ",(longlong *)0x6);
  FUN_140001270((longlong **)&local_78,1000);
  if (0xf < local_38) {
    pvVar2 = (void *)CONCAT71(uStack79,local_50);
    _Memory = pvVar2;
    if ((0xfff < local_38 + 1) &&
       (_Memory = *(void **)((longlong)pvVar2 + -8),
       0x1f < (ulonglong)((longlong)pvVar2 + (-8 - (longlong)_Memory)))) {
      _invalid_parameter_noinfo_noreturn();
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
    free(_Memory);
  }
  FUN_1400047b0(local_30 ^ (ulonglong)auStack152);
  return;
}



undefined8 FUN_140002490(void)

{
  undefined local_28;
  undefined8 local_18;
  undefined8 local_10;
  
  FUN_1400017c0();
  FUN_1400019e0();
  FUN_140002100();
  system("cls");
  system("color B1");
  local_10 = 0xf;
  local_18 = 0;
  local_28 = 0;
  FUN_1400036b0((longlong **)&local_28,"A short game made by @Kbent1_dev \n",(longlong *)0x22);
  FUN_140001270((longlong **)&local_28,100);
  local_18 = 0;
  local_10 = 0xf;
  local_28 = 0;
  FUN_1400036b0((longlong **)&local_28,"for the Weekly Game Jam - Week 117\n",(longlong *)0x23);
  FUN_140001270((longlong **)&local_28,100);
  local_18 = 0;
  local_10 = 0xf;
  local_28 = 0;
  FUN_1400036b0((longlong **)&local_28,"Week 117 Theme: \'Not a Bug\'\n",(longlong *)0x1c);
  FUN_140001270((longlong **)&local_28,100);
  local_18 = 0;
  local_10 = 0xf;
  local_28 = 0;
  FUN_1400036b0((longlong **)&local_28,"Thanks for playing :D !",(longlong *)0x17);
  FUN_140001270((longlong **)&local_28,100);
  FUN_1400013e0();
  return 0;
}



// WARNING: Exceeded maximum restarts with more pending

void FUN_1400025a0(longlong param_1,locale *param_2)

{
  bool bVar1;
  codecvt_base *this;
  
  this = (codecvt_base *)FUN_140003df0(param_2);
  bVar1 = std::codecvt_base::always_noconv(this);
  if (bVar1 != false) {
    *(undefined8 *)(param_1 + 0x68) = 0;
    return;
  }
  *(codecvt_base **)(param_1 + 0x68) = this;
                    // WARNING: Could not recover jumptable at 0x0001400025e9. Too many branches
                    // WARNING: Treating indirect jump as call
  std::basic_streambuf<char,struct_std::char_traits<char>_>::_Init(param_1);
  return;
}



undefined8 FUN_1400025f0(longlong *param_1)

{
  int iVar1;
  
  if (param_1[0x10] != 0) {
    iVar1 = (**(code **)(*param_1 + 0x18))(param_1,0xffffffff);
    if (iVar1 != -1) {
      iVar1 = fflush((FILE *)param_1[0x10]);
      if (iVar1 < 0) {
        return 0xffffffff;
      }
    }
  }
  return 0;
}



void FUN_140002640(basic_streambuf_char_struct_std__char_traits_char___ *param_1,char *param_2,
                  size_t param_3)

{
  longlong lVar1;
  undefined8 uVar2;
  int iVar3;
  undefined auStack88 [32];
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  ulonglong local_20;
  
  local_20 = DAT_14000a010 ^ (ulonglong)auStack88;
  if ((param_2 != (char *)0x0) || (iVar3 = 4, param_3 != 0)) {
    iVar3 = 0;
  }
  if ((*(FILE **)(param_1 + 0x80) != (FILE *)0x0) &&
     (iVar3 = setvbuf(*(FILE **)(param_1 + 0x80),param_2,iVar3,param_3), iVar3 == 0)) {
    lVar1 = *(longlong *)(param_1 + 0x80);
    param_1[0x7c] = (basic_streambuf_char_struct_std__char_traits_char___)0x1;
    param_1[0x71] = (basic_streambuf_char_struct_std__char_traits_char___)0x0;
    std::basic_streambuf<char,struct_std::char_traits<char>_>::_Init(param_1);
    if (lVar1 != 0) {
      local_38 = 0;
      local_30 = 0;
      local_28 = 0;
      _get_stream_buffer_pointers(lVar1,&local_38,&local_30,&local_28);
      *(undefined8 *)(param_1 + 0x18) = local_38;
      *(undefined8 *)(param_1 + 0x20) = local_38;
      *(undefined8 *)(param_1 + 0x38) = local_30;
      *(undefined8 *)(param_1 + 0x40) = local_30;
      *(undefined8 *)(param_1 + 0x50) = local_28;
      *(undefined8 *)(param_1 + 0x58) = local_28;
    }
    uVar2 = DAT_14000a8c8;
    *(longlong *)(param_1 + 0x80) = lVar1;
    *(undefined8 *)(param_1 + 0x74) = uVar2;
    *(undefined8 *)(param_1 + 0x68) = 0;
  }
  FUN_1400047b0(local_20 ^ (ulonglong)auStack88);
  return;
}



void FUN_140002740(longlong *param_1,longlong *param_2,longlong *param_3)

{
  longlong *plVar1;
  char cVar2;
  int iVar3;
  longlong lVar4;
  undefined auStack72 [32];
  longlong local_28;
  ulonglong local_20;
  
  local_20 = DAT_14000a010 ^ (ulonglong)auStack72;
  local_28 = param_3[1] + *param_3;
  if (param_1[0x10] != 0) {
    cVar2 = FUN_140003540(param_1);
    if (cVar2 != '\0') {
      iVar3 = fsetpos((FILE *)param_1[0x10],&local_28);
      if (iVar3 == 0) {
        lVar4 = param_3[2];
        *(longlong *)((longlong)param_1 + 0x74) = lVar4;
        if (*(longlong **)param_1[3] == param_1 + 0xe) {
          plVar1 = (longlong *)param_1[0x11];
          lVar4 = param_1[0x12];
          *(longlong **)param_1[3] = plVar1;
          *(longlong **)param_1[7] = plVar1;
          *(int *)param_1[10] = (int)lVar4 - (int)plVar1;
          lVar4 = *(longlong *)((longlong)param_1 + 0x74);
        }
        *param_2 = local_28;
        param_2[1] = 0;
        param_2[2] = lVar4;
        goto LAB_1400027fb;
      }
    }
  }
  *param_2 = -1;
  param_2[1] = 0;
  param_2[2] = 0;
LAB_1400027fb:
  FUN_1400047b0(local_20 ^ (ulonglong)auStack72);
  return;
}



void FUN_140002820(longlong *param_1,fpos_t *param_2,longlong param_3,int param_4)

{
  longlong *plVar1;
  longlong lVar2;
  fpos_t fVar3;
  char cVar4;
  int iVar5;
  undefined auStack88 [32];
  fpos_t local_38;
  ulonglong local_30;
  
  local_30 = DAT_14000a010 ^ (ulonglong)auStack88;
  if (((*(longlong **)param_1[7] == param_1 + 0xe) && (param_4 == 1)) && (param_1[0xd] == 0)) {
    param_3 = param_3 + -1;
  }
  if (param_1[0x10] != 0) {
    cVar4 = FUN_140003540(param_1);
    if (cVar4 != '\0') {
      if ((param_3 != 0) || (param_4 != 1)) {
        iVar5 = _fseeki64((FILE *)param_1[0x10],param_3,param_4);
        if (iVar5 != 0) goto LAB_1400028f6;
      }
      iVar5 = fgetpos((FILE *)param_1[0x10],&local_38);
      if (iVar5 == 0) {
        if (*(longlong **)param_1[3] == param_1 + 0xe) {
          plVar1 = (longlong *)param_1[0x11];
          lVar2 = param_1[0x12];
          *(longlong **)param_1[3] = plVar1;
          *(longlong **)param_1[7] = plVar1;
          *(int *)param_1[10] = (int)lVar2 - (int)plVar1;
        }
        fVar3 = *(fpos_t *)((longlong)param_1 + 0x74);
        *param_2 = local_38;
        param_2[2] = fVar3;
        param_2[1] = 0;
        goto LAB_14000290b;
      }
    }
  }
LAB_1400028f6:
  *param_2 = -1;
  param_2[1] = 0;
  param_2[2] = 0;
LAB_14000290b:
  FUN_1400047b0(local_30 ^ (ulonglong)auStack88);
  return;
}



// WARNING: Exceeded maximum restarts with more pending

longlong FUN_140002930(longlong param_1,void *param_2,size_t param_3)

{
  longlong lVar1;
  size_t sVar2;
  int iVar3;
  size_t _Count;
  
  if (*(longlong *)(param_1 + 0x68) != 0) {
                    // WARNING: Could not recover jumptable at 0x000140002960. Too many branches
                    // WARNING: Treating indirect jump as call
    lVar1 = std::basic_streambuf<char,struct_std::char_traits<char>_>::xsputn();
    return lVar1;
  }
  if (**(void ***)(param_1 + 0x40) == (void *)0x0) {
    iVar3 = 0;
  }
  else {
    iVar3 = **(int **)(param_1 + 0x58);
  }
  _Count = param_3;
  if (0 < (longlong)param_3) {
    if (0 < iVar3) {
      sVar2 = (longlong)iVar3;
      if ((longlong)param_3 < (longlong)iVar3) {
        sVar2 = param_3;
      }
      memcpy(**(void ***)(param_1 + 0x40),param_2,sVar2);
      _Count = param_3 - sVar2;
      param_2 = (void *)((longlong)param_2 + sVar2);
      **(int **)(param_1 + 0x58) = **(int **)(param_1 + 0x58) - (int)sVar2;
      **(longlong **)(param_1 + 0x40) = **(longlong **)(param_1 + 0x40) + (longlong)(int)sVar2;
      if ((longlong)_Count < 1) goto LAB_1400029e3;
    }
    if (*(FILE **)(param_1 + 0x80) != (FILE *)0x0) {
      sVar2 = fwrite(param_2,1,_Count,*(FILE **)(param_1 + 0x80));
      _Count = _Count - sVar2;
    }
  }
LAB_1400029e3:
  return param_3 - _Count;
}



// WARNING: Exceeded maximum restarts with more pending

longlong FUN_140002a10(longlong param_1,void *param_2,ulonglong param_3)

{
  undefined8 uVar1;
  longlong lVar2;
  size_t sVar3;
  int iVar4;
  ulonglong _Size;
  ulonglong _Count;
  
  if ((longlong)param_3 < 1) {
    return 0;
  }
  if (*(longlong *)(param_1 + 0x68) != 0) {
                    // WARNING: Could not recover jumptable at 0x000140002a41. Too many branches
                    // WARNING: Treating indirect jump as call
    lVar2 = std::basic_streambuf<char,struct_std::char_traits<char>_>::xsgetn();
    return lVar2;
  }
  if (**(void ***)(param_1 + 0x38) == (void *)0x0) {
    iVar4 = 0;
  }
  else {
    iVar4 = **(int **)(param_1 + 0x50);
  }
  _Count = param_3;
  if (iVar4 != 0) {
    _Size = param_3;
    if ((ulonglong)(longlong)iVar4 < param_3) {
      _Size = (longlong)iVar4;
    }
    memcpy(param_2,**(void ***)(param_1 + 0x38),_Size);
    _Count = param_3 - _Size;
    param_2 = (void *)((longlong)param_2 + _Size);
    **(int **)(param_1 + 0x50) = **(int **)(param_1 + 0x50) - (int)_Size;
    **(longlong **)(param_1 + 0x38) = **(longlong **)(param_1 + 0x38) + (longlong)(int)_Size;
  }
  if (*(longlong *)(param_1 + 0x80) != 0) {
    if (**(longlong **)(param_1 + 0x18) == param_1 + 0x70) {
      lVar2 = *(longlong *)(param_1 + 0x88);
      uVar1 = *(undefined8 *)(param_1 + 0x90);
      **(longlong **)(param_1 + 0x18) = lVar2;
      **(longlong **)(param_1 + 0x38) = lVar2;
      **(int **)(param_1 + 0x50) = (int)uVar1 - (int)lVar2;
    }
    do {
      if (_Count < 0x1000) {
        if (_Count != 0) {
          sVar3 = fread(param_2,1,_Count,*(FILE **)(param_1 + 0x80));
          _Count = _Count - sVar3;
        }
        break;
      }
      sVar3 = fread(param_2,1,0xfff,*(FILE **)(param_1 + 0x80));
      _Count = _Count - sVar3;
      param_2 = (void *)((longlong)param_2 + sVar3);
    } while (sVar3 == 0xfff);
  }
  return param_3 - _Count;
}



// WARNING: Type propagation algorithm not settling

void FUN_140002b70(longlong param_1)

{
  ulonglong uVar1;
  undefined8 uVar2;
  longlong lVar3;
  void *pvVar4;
  uint uVar5;
  int iVar6;
  undefined *puVar7;
  undefined *extraout_RAX;
  void *_Memory;
  char *pcVar8;
  char *local_48;
  char *local_40;
  char local_38;
  char local_37 [7];
  undefined8 local_30;
  char *local_20;
  char *local_18;
  ulonglong local_10;
  
  local_10 = DAT_14000a010 ^ (ulonglong)&stack0xffffffffffffff78;
  uVar1 = **(ulonglong **)(param_1 + 0x38);
  if (uVar1 != 0) {
    iVar6 = **(int **)(param_1 + 0x50);
    if (uVar1 < uVar1 + (longlong)iVar6) {
      **(int **)(param_1 + 0x50) = iVar6 + -1;
      **(longlong **)(param_1 + 0x38) = **(longlong **)(param_1 + 0x38) + 1;
      goto LAB_140002e10;
    }
  }
  if (*(longlong *)(param_1 + 0x80) != 0) {
    if (**(longlong **)(param_1 + 0x18) == param_1 + 0x70) {
      uVar2 = *(undefined8 *)(param_1 + 0x90);
      lVar3 = *(longlong *)(param_1 + 0x88);
      **(longlong **)(param_1 + 0x18) = lVar3;
      **(longlong **)(param_1 + 0x38) = lVar3;
      **(int **)(param_1 + 0x50) = (int)uVar2 - (int)lVar3;
    }
    if (*(longlong *)(param_1 + 0x68) != 0) {
      local_20 = (char *)0x0;
      local_18 = (char *)0xf;
      local_30._0_1_ = '\0';
      uVar5 = fgetc(*(FILE **)(param_1 + 0x80));
      pcVar8 = local_20;
      while (local_20 = pcVar8, uVar5 != 0xffffffff) {
        if (pcVar8 < local_18) {
          local_20 = pcVar8 + 1;
          puVar7 = (undefined *)&local_30;
          if ((char *)0xf < local_18) {
            puVar7 = (undefined *)CONCAT71(local_30._1_7_,(char)local_30);
          }
          puVar7[(longlong)pcVar8] = (char)uVar5;
          pcVar8[(longlong)(puVar7 + 1)] = '\0';
        }
        else {
          FUN_140003ef0((void **)&local_30,local_18,(ulonglong)uVar5,(char)uVar5);
        }
        puVar7 = (undefined *)&local_30;
        if ((char *)0xf < local_18) {
          puVar7 = (undefined *)CONCAT71(local_30._1_7_,(char)local_30);
        }
        pcVar8 = (char *)&local_30;
        if ((char *)0xf < local_18) {
          pcVar8 = (char *)CONCAT71(local_30._1_7_,(char)local_30);
        }
        iVar6 = std::codecvt<char,char,struct__Mbstatet>::in
                          (*(codecvt_char_char_struct__Mbstatet_ **)(param_1 + 0x68),
                           (_Mbstatet *)(param_1 + 0x74),pcVar8,local_20 + (longlong)puVar7,
                           &local_48,&local_38,local_37,&local_40);
        if ((iVar6 < 0) || (1 < iVar6)) break;
        puVar7 = (undefined *)&local_30;
        if (local_40 != &local_38) goto LAB_140002da5;
        if ((char *)0xf < local_18) {
          puVar7 = (undefined *)CONCAT71(local_30._1_7_,(char)local_30);
        }
        pcVar8 = local_48 + -(longlong)puVar7;
        if (local_20 < local_48 + -(longlong)puVar7) {
          pcVar8 = local_20;
        }
        puVar7 = (undefined *)&local_30;
        if ((char *)0xf < local_18) {
          puVar7 = (undefined *)CONCAT71(local_30._1_7_,(char)local_30);
        }
        local_20 = local_20 + -(longlong)pcVar8;
        memmove(puVar7,puVar7 + (longlong)pcVar8,(size_t)(local_20 + 1));
        uVar5 = fgetc(*(FILE **)(param_1 + 0x80));
        pcVar8 = local_20;
      }
      do {
        if (local_18 < (char *)0x10) goto LAB_140002e10;
        pvVar4 = (void *)CONCAT71(local_30._1_7_,(char)local_30);
        _Memory = pvVar4;
        if ((local_18 + 1 < (char *)0x1000) ||
           (_Memory = *(void **)((longlong)pvVar4 + -8),
           (ulonglong)((longlong)pvVar4 + (-8 - (longlong)_Memory)) < 0x20)) {
          free(_Memory);
          goto LAB_140002e10;
        }
        _invalid_parameter_noinfo_noreturn();
        puVar7 = extraout_RAX;
LAB_140002da5:
        if ((char *)0xf < local_18) {
          puVar7 = (undefined *)CONCAT71(local_30._1_7_,(char)local_30);
        }
        pcVar8 = local_20 + -(longlong)local_48 + (longlong)puVar7;
        while (0 < (longlong)pcVar8) {
          pcVar8 = pcVar8 + -1;
          ungetc((int)local_48[(longlong)pcVar8],*(FILE **)(param_1 + 0x80));
        }
      } while( true );
    }
    fgetc(*(FILE **)(param_1 + 0x80));
  }
LAB_140002e10:
  FUN_1400047b0(local_10 ^ (ulonglong)&stack0xffffffffffffff78);
  return;
}



ulonglong FUN_140002e40(longlong *param_1)

{
  byte *pbVar1;
  ulonglong uVar2;
  
  pbVar1 = *(byte **)param_1[7];
  if ((pbVar1 != (byte *)0x0) && (pbVar1 < pbVar1 + *(int *)param_1[10])) {
    return (ulonglong)*pbVar1;
  }
  uVar2 = (**(code **)(*param_1 + 0x38))(param_1);
  if ((int)uVar2 == -1) {
    return uVar2;
  }
  (**(code **)(*param_1 + 0x20))(param_1,uVar2 & 0xffffffff);
  return uVar2 & 0xffffffff;
}



uint FUN_140002eb0(longlong param_1,uint param_2)

{
  undefined *puVar1;
  ulonglong uVar2;
  undefined *puVar3;
  uint uVar4;
  int iVar5;
  
  uVar2 = **(ulonglong **)(param_1 + 0x38);
  if (((uVar2 != 0) && (**(ulonglong **)(param_1 + 0x18) < uVar2)) &&
     ((param_2 == 0xffffffff || (*(byte *)(uVar2 - 1) == param_2)))) {
    **(int **)(param_1 + 0x50) = **(int **)(param_1 + 0x50) + 1;
    **(longlong **)(param_1 + 0x38) = **(longlong **)(param_1 + 0x38) + -1;
    uVar4 = 0;
    if (param_2 != 0xffffffff) {
      uVar4 = param_2;
    }
    return uVar4;
  }
  if ((*(FILE **)(param_1 + 0x80) != (FILE *)0x0) && (param_2 != 0xffffffff)) {
    if ((*(longlong *)(param_1 + 0x68) == 0) &&
       (iVar5 = ungetc(param_2 & 0xff,*(FILE **)(param_1 + 0x80)), iVar5 != -1)) {
      return param_2;
    }
    puVar1 = (undefined *)(param_1 + 0x70);
    if ((undefined *)**(longlong **)(param_1 + 0x38) != puVar1) {
      *puVar1 = (char)param_2;
      puVar3 = (undefined *)**(longlong **)(param_1 + 0x18);
      if (puVar3 != puVar1) {
        *(undefined **)(param_1 + 0x88) = puVar3;
        *(longlong *)(param_1 + 0x90) =
             (longlong)**(int **)(param_1 + 0x50) + **(longlong **)(param_1 + 0x38);
      }
      **(longlong **)(param_1 + 0x18) = (longlong)puVar1;
      **(longlong **)(param_1 + 0x38) = (longlong)puVar1;
      **(int **)(param_1 + 0x50) = ((int)param_1 - (int)puVar1) + 0x71;
      return param_2;
    }
  }
  return 0xffffffff;
}



void FUN_140002f90(basic_streambuf_char_struct_std__char_traits_char___ *param_1,int param_2)

{
  ulonglong uVar1;
  undefined8 uVar2;
  basic_streambuf_char_struct_std__char_traits_char___ *pbVar3;
  int iVar4;
  char *pcVar5;
  char cVar6;
  char *local_48;
  char *local_40;
  char local_38;
  char local_37 [7];
  char local_30 [32];
  ulonglong local_10;
  
  local_10 = DAT_14000a010 ^ (ulonglong)&stack0xffffffffffffff78;
  if (param_2 != -1) {
    uVar1 = **(ulonglong **)(param_1 + 0x40);
    cVar6 = (char)param_2;
    if ((uVar1 == 0) || ((longlong)**(int **)(param_1 + 0x58) + uVar1 <= uVar1)) {
      if (*(longlong *)(param_1 + 0x80) != 0) {
        if (**(basic_streambuf_char_struct_std__char_traits_char___ ***)(param_1 + 0x18) ==
            param_1 + 0x70) {
          uVar2 = *(undefined8 *)(param_1 + 0x90);
          pbVar3 = *(basic_streambuf_char_struct_std__char_traits_char___ **)(param_1 + 0x88);
          **(basic_streambuf_char_struct_std__char_traits_char___ ***)(param_1 + 0x18) = pbVar3;
          **(basic_streambuf_char_struct_std__char_traits_char___ ***)(param_1 + 0x38) = pbVar3;
          **(int **)(param_1 + 0x50) = (int)uVar2 - (int)pbVar3;
        }
        if (*(codecvt_char_char_struct__Mbstatet_ **)(param_1 + 0x68) ==
            (codecvt_char_char_struct__Mbstatet_ *)0x0) {
          fputc((int)cVar6,*(FILE **)(param_1 + 0x80));
        }
        else {
          local_38 = cVar6;
          iVar4 = std::codecvt<char,char,struct__Mbstatet>::out
                            (*(codecvt_char_char_struct__Mbstatet_ **)(param_1 + 0x68),
                             (_Mbstatet *)(param_1 + 0x74),&local_38,local_37,&local_40,local_30,
                             (char *)&local_10,&local_48);
          if (-1 < iVar4) {
            if (iVar4 < 2) {
              local_48 = local_48 + -(longlong)local_30;
              if ((local_48 == (char *)0x0) ||
                 (pcVar5 = (char *)fwrite(local_30,1,(size_t)local_48,*(FILE **)(param_1 + 0x80)),
                 local_48 == pcVar5)) {
                param_1[0x71] = (basic_streambuf_char_struct_std__char_traits_char___)0x1;
              }
            }
            else {
              if (iVar4 == 3) {
                fputc((int)local_38,*(FILE **)(param_1 + 0x80));
              }
            }
          }
        }
      }
    }
    else {
      pcVar5 = std::basic_streambuf<char,struct_std::char_traits<char>_>::_Pninc(param_1);
      *pcVar5 = cVar6;
    }
  }
  FUN_1400047b0(local_10 ^ (ulonglong)&stack0xffffffffffffff78);
  return;
}



void FUN_140003130(longlong param_1)

{
  if (*(FILE **)(param_1 + 0x80) != (FILE *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00014000313c. Too many branches
                    // WARNING: Treating indirect jump as call
    _unlock_file(*(FILE **)(param_1 + 0x80));
    return;
  }
  return;
}



void FUN_140003150(longlong param_1)

{
  if (*(FILE **)(param_1 + 0x80) != (FILE *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00014000315c. Too many branches
                    // WARNING: Treating indirect jump as call
    _lock_file(*(FILE **)(param_1 + 0x80));
    return;
  }
  return;
}



void FUN_140003170(longlong *param_1)

{
  longlong *this;
  locale lVar1;
  bool bVar2;
  int *piVar3;
  _iobuf *p_Var5;
  undefined7 extraout_var;
  codecvt_base *this_00;
  code **ppcVar6;
  undefined auStack88 [40];
  longlong *local_30;
  longlong local_28;
  longlong local_20;
  longlong local_18;
  ulonglong local_10;
  longlong lVar4;
  
  local_10 = DAT_14000a010 ^ (ulonglong)auStack88;
  this = param_1 + 1;
  if (param_1[0x11] == 0) {
    p_Var5 = std::_Fiopen("GtA6.txt",2,0x40);
    if (p_Var5 == (_iobuf *)0x0) {
      lVar4 = *param_1;
      goto LAB_1400031a7;
    }
    *(undefined *)((longlong)param_1 + 0x84) = 1;
    *(undefined *)((longlong)param_1 + 0x79) = 0;
    std::basic_streambuf<char,struct_std::char_traits<char>_>::_Init
              ((basic_streambuf_char_struct_std__char_traits_char___ *)this);
    local_28 = 0;
    local_20 = 0;
    local_18 = 0;
    _get_stream_buffer_pointers(p_Var5,&local_28,&local_20,&local_18);
    param_1[4] = local_28;
    param_1[5] = local_28;
    param_1[8] = local_20;
    param_1[9] = local_20;
    param_1[0xb] = local_18;
    param_1[0xc] = local_18;
    param_1[0x11] = (longlong)p_Var5;
    *(undefined8 *)((longlong)param_1 + 0x7c) = DAT_14000a8c8;
    param_1[0xe] = 0;
    lVar1 = std::basic_streambuf<char,struct_std::char_traits<char>_>::getloc
                      ((basic_streambuf_char_struct_std__char_traits_char___ *)this);
    this_00 = (codecvt_base *)FUN_140003df0((locale *)CONCAT71(extraout_var,lVar1));
    bVar2 = std::codecvt_base::always_noconv(this_00);
    if (bVar2 == false) {
      param_1[0xe] = (longlong)this_00;
      std::basic_streambuf<char,struct_std::char_traits<char>_>::_Init
                ((basic_streambuf_char_struct_std__char_traits_char___ *)this);
    }
    else {
      param_1[0xe] = 0;
    }
    if (local_30 != (longlong *)0x0) {
      ppcVar6 = (code **)(**(code **)(*local_30 + 0x10))();
      if (ppcVar6 != (code **)0x0) {
        (**(code **)*ppcVar6)(ppcVar6);
      }
    }
    piVar3 = (int *)(*param_1 + 4);
    if (this != (longlong *)0x0) {
      std::basic_ios<char,struct_std::char_traits<char>_>::clear
                ((basic_ios_char_struct_std__char_traits_char___ *)
                 ((longlong)*piVar3 + (longlong)param_1),0,false);
      goto LAB_1400031be;
    }
  }
  else {
    lVar4 = *param_1;
LAB_1400031a7:
    piVar3 = (int *)(lVar4 + 4);
  }
  std::basic_ios<char,struct_std::char_traits<char>_>::setstate
            ((basic_ios_char_struct_std__char_traits_char___ *)
             ((longlong)*piVar3 + (longlong)param_1),2,false);
LAB_1400031be:
  FUN_1400047b0(local_10 ^ (ulonglong)auStack88);
  return;
}



longlong * FUN_140003300(longlong *param_1)

{
  undefined **this;
  
  *param_1 = (longlong)&DAT_140006ae0;
  std::basic_ios<char,struct_std::char_traits<char>_>::
  basic_ios_char_struct_std__char_traits_char___
            ((basic_ios_char_struct_std__char_traits_char___ *)(param_1 + 0x15));
  this = (undefined **)(param_1 + 1);
  std::basic_ostream<char,struct_std::char_traits<char>_>::
  basic_ostream_char_struct_std__char_traits_char___
            ((basic_ostream_char_struct_std__char_traits_char___ *)param_1,
             (basic_streambuf_char_struct_std__char_traits_char___ *)this,false);
  *(undefined ***)((longlong)*(int *)(*param_1 + 4) + (longlong)param_1) =
       std::basic_ofstream<char,struct_std::char_traits<char>_>::vftable;
  *(int *)((longlong)*(int *)(*param_1 + 4) + -4 + (longlong)param_1) =
       *(int *)(*param_1 + 4) + -0xa8;
  std::basic_streambuf<char,struct_std::char_traits<char>_>::
  basic_streambuf_char_struct_std__char_traits_char___
            ((basic_streambuf_char_struct_std__char_traits_char___ *)this);
  *this = (undefined *)std::basic_filebuf<char,struct_std::char_traits<char>_>::vftable;
  *(undefined *)((longlong)param_1 + 0x84) = 0;
  *(undefined *)((longlong)param_1 + 0x79) = 0;
  std::basic_streambuf<char,struct_std::char_traits<char>_>::_Init
            ((basic_streambuf_char_struct_std__char_traits_char___ *)this);
  param_1[0x11] = 0;
  *(undefined8 *)((longlong)param_1 + 0x7c) = DAT_14000a8c8;
  param_1[0xe] = 0;
  return param_1;
}



void FUN_1400033d0(void **param_1)

{
  void *pvVar1;
  code *pcVar2;
  void *_Memory;
  
  if ((void *)0xf < param_1[3]) {
    pvVar1 = *param_1;
    _Memory = pvVar1;
    if ((0xfff < (longlong)param_1[3] + 1U) &&
       (_Memory = *(void **)((longlong)pvVar1 + -8),
       0x1f < (ulonglong)((longlong)pvVar1 + (-8 - (longlong)_Memory)))) {
      _invalid_parameter_noinfo_noreturn();
      pcVar2 = (code *)swi(3);
      (*pcVar2)();
      return;
    }
    free(_Memory);
  }
  param_1[2] = (void *)0x0;
  param_1[3] = (void *)0xf;
  *(undefined *)param_1 = 0;
  return;
}



undefined ** FUN_140003430(undefined **param_1,uint param_2)

{
  undefined *puVar1;
  undefined *puVar2;
  
  *param_1 = (undefined *)std::basic_filebuf<char,struct_std::char_traits<char>_>::vftable;
  if ((param_1[0x10] != (undefined *)0x0) && (*(undefined ***)param_1[3] == param_1 + 0xe)) {
    puVar1 = param_1[0x12];
    puVar2 = param_1[0x11];
    *(undefined **)param_1[3] = puVar2;
    *(undefined **)param_1[7] = puVar2;
    *(int *)param_1[10] = (int)puVar1 - (int)puVar2;
  }
  if (*(char *)((longlong)param_1 + 0x7c) != '\0') {
    FUN_140003630((longlong *)param_1);
  }
  std::basic_streambuf<char,struct_std::char_traits<char>_>::
  _basic_streambuf_char_struct_std__char_traits_char___
            ((basic_streambuf_char_struct_std__char_traits_char___ *)param_1);
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



longlong * FUN_1400034c0(longlong param_1,uint param_2)

{
  longlong *_Memory;
  
  _Memory = (longlong *)(param_1 + -0xa8);
  FUN_140001470(_Memory);
  if ((param_2 & 1) != 0) {
    free(_Memory);
  }
  return _Memory;
}



void FUN_140003500(longlong **param_1)

{
  longlong *plVar1;
  bool bVar2;
  
  bVar2 = std::uncaught_exception();
  if (bVar2 == false) {
    std::basic_ostream<char,struct_std::char_traits<char>_>::_Osfx
              ((basic_ostream_char_struct_std__char_traits_char___ *)*param_1);
  }
  plVar1 = *(longlong **)((longlong)*(int *)(**param_1 + 4) + 0x48 + (longlong)*param_1);
  if (plVar1 != (longlong *)0x0) {
    (**(code **)(*plVar1 + 0x10))();
  }
  return;
}



void FUN_140003540(longlong *param_1)

{
  int iVar1;
  char *local_38;
  char local_30 [32];
  ulonglong local_10;
  
  local_10 = DAT_14000a010 ^ (ulonglong)&stack0xffffffffffffff98;
  if ((param_1[0xd] == 0) || (*(char *)((longlong)param_1 + 0x71) == '\0')) {
    FUN_1400047b0(local_10 ^ (ulonglong)&stack0xffffffffffffff98);
    return;
  }
  iVar1 = (**(code **)(*param_1 + 0x18))(param_1,0xffffffff);
  if (iVar1 != -1) {
    iVar1 = std::codecvt<char,char,struct__Mbstatet>::unshift
                      ((codecvt_char_char_struct__Mbstatet_ *)param_1[0xd],
                       (_Mbstatet *)((longlong)param_1 + 0x74),local_30,(char *)&local_10,&local_38)
    ;
    if (iVar1 == 0) {
      *(undefined *)((longlong)param_1 + 0x71) = 0;
    }
    else {
      if (iVar1 != 1) {
        if (iVar1 == 3) {
          *(undefined *)((longlong)param_1 + 0x71) = 0;
        }
        goto LAB_1400035bc;
      }
    }
    if (local_38 + -(longlong)local_30 != (char *)0x0) {
      fwrite(local_30,1,(size_t)(local_38 + -(longlong)local_30),(FILE *)param_1[0x10]);
    }
  }
LAB_1400035bc:
  FUN_1400047b0(local_10 ^ (ulonglong)&stack0xffffffffffffff98);
  return;
}



longlong * FUN_140003630(longlong *param_1)

{
  char cVar1;
  int iVar2;
  longlong *plVar3;
  
  if (param_1[0x10] != 0) {
    cVar1 = FUN_140003540(param_1);
    plVar3 = param_1;
    if (cVar1 == '\0') {
      plVar3 = (longlong *)0x0;
    }
    iVar2 = fclose((FILE *)param_1[0x10]);
    if (iVar2 == 0) goto LAB_140003674;
  }
  plVar3 = (longlong *)0x0;
LAB_140003674:
  *(undefined *)((longlong)param_1 + 0x7c) = 0;
  *(undefined *)((longlong)param_1 + 0x71) = 0;
  std::basic_streambuf<char,struct_std::char_traits<char>_>::_Init
            ((basic_streambuf_char_struct_std__char_traits_char___ *)param_1);
  *(undefined8 *)((longlong)param_1 + 0x74) = DAT_14000a8c8;
  param_1[0x10] = 0;
  param_1[0xd] = 0;
  return plVar3;
}



longlong ** FUN_1400036b0(longlong **param_1,void *param_2,longlong *param_3)

{
  longlong *plVar1;
  code *pcVar2;
  void *pvVar3;
  longlong **pplVar4;
  longlong *plVar5;
  ulonglong uVar6;
  longlong *plVar7;
  longlong *plVar8;
  
  plVar1 = param_1[3];
  if (param_3 <= plVar1) {
    pplVar4 = param_1;
    if ((longlong *)0xf < plVar1) {
      pplVar4 = (longlong **)*param_1;
    }
    param_1[2] = param_3;
    memmove(pplVar4,param_2,(size_t)param_3);
    *(undefined *)((longlong)param_3 + (longlong)pplVar4) = 0;
    return param_1;
  }
  if ((longlong *)0x7fffffffffffffff < param_3) {
    FUN_140004200();
    pcVar2 = (code *)swi(3);
    pplVar4 = (longlong **)(*pcVar2)();
    return pplVar4;
  }
  plVar5 = (longlong *)((ulonglong)param_3 | 0xf);
  plVar8 = (longlong *)0x7fffffffffffffff;
  if (((plVar5 < (longlong *)0x8000000000000000) &&
      (plVar1 <= (longlong *)(0x7fffffffffffffff - ((ulonglong)plVar1 >> 1)))) &&
     (plVar7 = (longlong *)(((ulonglong)plVar1 >> 1) + (longlong)plVar1), plVar8 = plVar5,
     plVar5 < plVar7)) {
    plVar8 = plVar7;
  }
  uVar6 = (longlong)plVar8 + 1;
  if (plVar8 == (longlong *)0xffffffffffffffff) {
    uVar6 = 0xffffffffffffffff;
  }
  if (uVar6 < 0x1000) {
    if (uVar6 == 0) {
      plVar5 = (longlong *)0x0;
    }
    else {
      plVar5 = (longlong *)operator_new(uVar6);
    }
  }
  else {
    if (uVar6 + 0x27 <= uVar6) {
      FUN_140001110();
      pcVar2 = (code *)swi(3);
      pplVar4 = (longlong **)(*pcVar2)();
      return pplVar4;
    }
    pvVar3 = operator_new(uVar6 + 0x27);
    if (pvVar3 == (void *)0x0) goto LAB_1400037fa;
    plVar5 = (longlong *)((longlong)pvVar3 + 0x27U & 0xffffffffffffffe0);
    plVar5[-1] = (longlong)pvVar3;
  }
  param_1[2] = param_3;
  param_1[3] = plVar8;
  memcpy(plVar5,param_2,(size_t)param_3);
  *(undefined *)((longlong)param_3 + (longlong)plVar5) = 0;
  if ((longlong *)0xf < plVar1) {
    plVar8 = *param_1;
    plVar7 = plVar8;
    if ((0xfff < (longlong)plVar1 + 1U) &&
       (plVar7 = (longlong *)plVar8[-1],
       0x1f < (ulonglong)((longlong)plVar8 + (-8 - (longlong)plVar7)))) {
LAB_1400037fa:
      _invalid_parameter_noinfo_noreturn();
      pcVar2 = (code *)swi(3);
      pplVar4 = (longlong **)(*pcVar2)();
      return pplVar4;
    }
    free(plVar7);
  }
  *param_1 = plVar5;
  return param_1;
}



void ** FUN_140003810(void **param_1,void *param_2,void *param_3)

{
  void *pvVar1;
  void *pvVar2;
  void **ppvVar3;
  
  pvVar1 = param_1[2];
  pvVar2 = param_1[3];
  if (param_3 <= (void *)((longlong)pvVar2 - (longlong)pvVar1)) {
    param_1[2] = (void *)((longlong)pvVar1 + (longlong)param_3);
    ppvVar3 = param_1;
    if ((void *)0xf < pvVar2) {
      ppvVar3 = (void **)*param_1;
    }
    memmove((void *)((longlong)ppvVar3 + (longlong)pvVar1),param_2,(size_t)param_3);
    *(undefined *)((longlong)(void *)((longlong)ppvVar3 + (longlong)pvVar1) + (longlong)param_3) = 0
    ;
    return param_1;
  }
  ppvVar3 = FUN_140004050(param_1,(ulonglong)param_3,pvVar2,param_2,(size_t)param_3);
  return ppvVar3;
}



void FUN_1400038c0(locale *param_1)

{
  longlong lVar1;
  code *pcVar2;
  longlong *plVar3;
  __uint64 _Var4;
  _Locimp *p_Var5;
  longlong lVar6;
  undefined auStack72 [32];
  longlong *local_28;
  _Lockit local_20 [8];
  longlong *local_18;
  ulonglong local_10;
  
  local_10 = DAT_14000a010 ^ (ulonglong)auStack72;
  std::_Lockit::_Lockit(local_20,0);
  local_28 = DAT_14000a8c0;
  _Var4 = std::locale::id::operator_unsigned___int64((id *)id_exref);
  lVar1 = *(longlong *)(param_1 + 8);
  if (_Var4 < *(ulonglong *)(lVar1 + 0x18)) {
    lVar6 = *(longlong *)(*(longlong *)(lVar1 + 0x10) + _Var4 * 8);
    if (lVar6 != 0) goto LAB_14000398a;
  }
  else {
    lVar6 = 0;
  }
  if (*(char *)(lVar1 + 0x24) == '\0') {
LAB_140003940:
    if (lVar6 != 0) goto LAB_14000398a;
  }
  else {
    p_Var5 = std::locale::_Getgloballocale();
    if (_Var4 < *(ulonglong *)(p_Var5 + 0x18)) {
      lVar6 = *(longlong *)(*(longlong *)(p_Var5 + 0x10) + _Var4 * 8);
      goto LAB_140003940;
    }
  }
  if (local_28 == (longlong *)0x0) {
    _Var4 = std::ctype<char>::_Getcat((facet **)&local_28,param_1);
    plVar3 = local_28;
    if (_Var4 == 0xffffffffffffffff) {
      FUN_1400011e0();
      pcVar2 = (code *)swi(3);
      (*pcVar2)();
      return;
    }
    local_18 = local_28;
    std::_Facet_Register((_Facet_base *)local_28);
    (**(code **)(*plVar3 + 8))(plVar3);
    DAT_14000a8c0 = local_28;
  }
LAB_14000398a:
  std::_Lockit::__Lockit(local_20);
  FUN_1400047b0(local_10 ^ (ulonglong)auStack72);
  return;
}



longlong * FUN_1400039c0(longlong *param_1,char param_2)

{
  longlong *plVar1;
  longlong lVar2;
  bool bVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  longlong lVar7;
  longlong lVar8;
  int iVar9;
  
  iVar4 = 0;
  iVar6 = 0;
  lVar8 = *param_1;
  plVar1 = *(longlong **)((longlong)*(int *)(lVar8 + 4) + 0x48 + (longlong)param_1);
  if (plVar1 != (longlong *)0x0) {
    (**(code **)(*plVar1 + 8))();
    lVar8 = *param_1;
  }
  if (*(int *)((longlong)*(int *)(lVar8 + 4) + 0x10 + (longlong)param_1) == 0) {
    plVar1 = *(longlong **)((longlong)*(int *)(lVar8 + 4) + 0x50 + (longlong)param_1);
    if ((plVar1 == (longlong *)0x0) || (plVar1 == param_1)) {
      bVar3 = true;
    }
    else {
      std::basic_ostream<char,struct_std::char_traits<char>_>::flush
                ((basic_ostream_char_struct_std__char_traits_char___ *)plVar1);
      lVar8 = *param_1;
      bVar3 = *(int *)((longlong)*(int *)(lVar8 + 4) + 0x10 + (longlong)param_1) == 0;
    }
  }
  else {
    bVar3 = false;
  }
  if (bVar3) {
    lVar2 = *(longlong *)((longlong)*(int *)(lVar8 + 4) + 0x28 + (longlong)param_1);
    lVar7 = 0;
    if (1 < lVar2) {
      lVar7 = lVar2 + -1;
    }
    iVar9 = 4;
    iVar5 = 0;
    if ((*(uint *)((longlong)*(int *)(lVar8 + 4) + 0x18 + (longlong)param_1) & 0x1c0) == 0x40) {
LAB_140003ab3:
      iVar5 = std::basic_streambuf<char,struct_std::char_traits<char>_>::sputc
                        (*(basic_streambuf_char_struct_std__char_traits_char___ **)
                          ((longlong)*(int *)(lVar8 + 4) + 0x48 + (longlong)param_1),param_2);
      iVar6 = iVar4;
      if (iVar5 == -1) {
        iVar6 = iVar9;
      }
      while ((iVar6 == 0 && (0 < lVar7))) {
        iVar4 = std::basic_streambuf<char,struct_std::char_traits<char>_>::sputc
                          (*(basic_streambuf_char_struct_std__char_traits_char___ **)
                            ((longlong)*(int *)(*param_1 + 4) + 0x48 + (longlong)param_1),
                           *(char *)((longlong)*(int *)(*param_1 + 4) + 0x58 + (longlong)param_1));
        if (iVar4 == -1) {
          iVar6 = iVar9;
        }
        lVar7 = lVar7 + -1;
      }
    }
    else {
      while (iVar4 = iVar5, iVar6 == 0) {
        if (lVar7 < 1) {
          lVar8 = *param_1;
          goto LAB_140003ab3;
        }
        iVar4 = std::basic_streambuf<char,struct_std::char_traits<char>_>::sputc
                          (*(basic_streambuf_char_struct_std__char_traits_char___ **)
                            ((longlong)*(int *)(*param_1 + 4) + 0x48 + (longlong)param_1),
                           *(char *)((longlong)*(int *)(*param_1 + 4) + 0x58 + (longlong)param_1));
        iVar5 = 0;
        if (iVar4 == -1) {
          iVar5 = 4;
          iVar6 = iVar9;
        }
        lVar7 = lVar7 + -1;
      }
    }
  }
  *(undefined8 *)((longlong)*(int *)(*param_1 + 4) + 0x28 + (longlong)param_1) = 0;
  std::basic_ios<char,struct_std::char_traits<char>_>::setstate
            ((basic_ios_char_struct_std__char_traits_char___ *)
             ((longlong)*(int *)(*param_1 + 4) + (longlong)param_1),iVar6,false);
  bVar3 = std::uncaught_exception();
  if (bVar3 == false) {
    std::basic_ostream<char,struct_std::char_traits<char>_>::_Osfx
              ((basic_ostream_char_struct_std__char_traits_char___ *)param_1);
  }
  plVar1 = *(longlong **)((longlong)*(int *)(*param_1 + 4) + 0x48 + (longlong)param_1);
  if (plVar1 != (longlong *)0x0) {
    (**(code **)(*plVar1 + 0x10))();
  }
  return param_1;
}



longlong * FUN_140003b80(longlong *param_1,char *param_2)

{
  longlong *plVar1;
  bool bVar2;
  int iVar3;
  __int64 _Var4;
  longlong lVar5;
  int iVar6;
  longlong lVar7;
  longlong lVar8;
  
  iVar6 = 0;
  lVar8 = -1;
  do {
    lVar8 = lVar8 + 1;
  } while (param_2[lVar8] != '\0');
  lVar5 = *param_1;
  lVar7 = *(longlong *)((longlong)*(int *)(lVar5 + 4) + 0x28 + (longlong)param_1);
  if ((lVar7 < 1) || (lVar7 <= lVar8)) {
    lVar7 = 0;
  }
  else {
    lVar7 = lVar7 - lVar8;
  }
  plVar1 = *(longlong **)((longlong)*(int *)(lVar5 + 4) + 0x48 + (longlong)param_1);
  if (plVar1 != (longlong *)0x0) {
    (**(code **)(*plVar1 + 8))(plVar1);
    lVar5 = *param_1;
  }
  if (*(int *)((longlong)*(int *)(lVar5 + 4) + 0x10 + (longlong)param_1) == 0) {
    plVar1 = *(longlong **)((longlong)*(int *)(lVar5 + 4) + 0x50 + (longlong)param_1);
    if ((plVar1 == (longlong *)0x0) || (plVar1 == param_1)) {
      bVar2 = true;
    }
    else {
      std::basic_ostream<char,struct_std::char_traits<char>_>::flush
                ((basic_ostream_char_struct_std__char_traits_char___ *)plVar1);
      lVar5 = *param_1;
      bVar2 = *(int *)((longlong)*(int *)(lVar5 + 4) + 0x10 + (longlong)param_1) == 0;
    }
  }
  else {
    bVar2 = false;
  }
  if (bVar2) {
    if ((*(uint *)((longlong)*(int *)(lVar5 + 4) + 0x18 + (longlong)param_1) & 0x1c0) != 0x40) {
      while (0 < lVar7) {
        iVar3 = std::basic_streambuf<char,struct_std::char_traits<char>_>::sputc
                          (*(basic_streambuf_char_struct_std__char_traits_char___ **)
                            ((longlong)*(int *)(*param_1 + 4) + 0x48 + (longlong)param_1),
                           *(char *)((longlong)*(int *)(*param_1 + 4) + 0x58 + (longlong)param_1));
        if (iVar3 == -1) goto LAB_140003cc9;
        lVar7 = lVar7 + -1;
      }
      lVar5 = *param_1;
    }
    _Var4 = std::basic_streambuf<char,struct_std::char_traits<char>_>::sputn
                      (*(basic_streambuf_char_struct_std__char_traits_char___ **)
                        ((longlong)*(int *)(lVar5 + 4) + 0x48 + (longlong)param_1),param_2,lVar8);
    if (_Var4 == lVar8) {
      while (0 < lVar7) {
        iVar3 = std::basic_streambuf<char,struct_std::char_traits<char>_>::sputc
                          (*(basic_streambuf_char_struct_std__char_traits_char___ **)
                            ((longlong)*(int *)(*param_1 + 4) + 0x48 + (longlong)param_1),
                           *(char *)((longlong)*(int *)(*param_1 + 4) + 0x58 + (longlong)param_1));
        if (iVar3 == -1) goto LAB_140003cc9;
        lVar7 = lVar7 + -1;
      }
    }
    else {
LAB_140003cc9:
      iVar6 = 4;
    }
    *(undefined8 *)((longlong)*(int *)(*param_1 + 4) + 0x28 + (longlong)param_1) = 0;
  }
  else {
    iVar6 = 4;
  }
  std::basic_ios<char,struct_std::char_traits<char>_>::setstate
            ((basic_ios_char_struct_std__char_traits_char___ *)
             ((longlong)*(int *)(*param_1 + 4) + (longlong)param_1),iVar6,false);
  bVar2 = std::uncaught_exception();
  if (bVar2 == false) {
    std::basic_ostream<char,struct_std::char_traits<char>_>::_Osfx
              ((basic_ostream_char_struct_std__char_traits_char___ *)param_1);
  }
  plVar1 = *(longlong **)((longlong)*(int *)(*param_1 + 4) + 0x48 + (longlong)param_1);
  if (plVar1 != (longlong *)0x0) {
    (**(code **)(*plVar1 + 0x10))();
  }
  return param_1;
}



void ** FUN_140003d50(void **param_1,undefined8 *param_2)

{
  void **ppvVar1;
  ulonglong uVar2;
  
  param_1[2] = (void *)0x0;
  param_1[3] = (void *)0xf;
  *(undefined *)param_1 = 0;
  ppvVar1 = (void **)(param_2 + 2);
  uVar2 = (longlong)*ppvVar1 + 1;
  if (0xf < uVar2) {
    FUN_1400045d0(param_1,uVar2);
    param_1[2] = (void *)0x0;
  }
  if (0xf < (ulonglong)param_2[3]) {
    param_2 = (undefined8 *)*param_2;
  }
  FUN_140003810(param_1,param_2,*ppvVar1);
  FUN_140003810(param_1,&DAT_14000664c,(void *)0x1);
  return param_1;
}



void FUN_140003df0(locale *param_1)

{
  longlong lVar1;
  code *pcVar2;
  longlong *plVar3;
  __uint64 _Var4;
  _Locimp *p_Var5;
  longlong lVar6;
  undefined auStack72 [32];
  longlong *local_28;
  _Lockit local_20 [8];
  longlong *local_18;
  ulonglong local_10;
  
  local_10 = DAT_14000a010 ^ (ulonglong)auStack72;
  std::_Lockit::_Lockit(local_20,0);
  local_28 = DAT_14000a8b8;
  _Var4 = std::locale::id::operator_unsigned___int64((id *)id_exref);
  lVar1 = *(longlong *)(param_1 + 8);
  if (_Var4 < *(ulonglong *)(lVar1 + 0x18)) {
    lVar6 = *(longlong *)(*(longlong *)(lVar1 + 0x10) + _Var4 * 8);
    if (lVar6 != 0) goto LAB_140003eba;
  }
  else {
    lVar6 = 0;
  }
  if (*(char *)(lVar1 + 0x24) == '\0') {
LAB_140003e70:
    if (lVar6 != 0) goto LAB_140003eba;
  }
  else {
    p_Var5 = std::locale::_Getgloballocale();
    if (_Var4 < *(ulonglong *)(p_Var5 + 0x18)) {
      lVar6 = *(longlong *)(*(longlong *)(p_Var5 + 0x10) + _Var4 * 8);
      goto LAB_140003e70;
    }
  }
  if (local_28 == (longlong *)0x0) {
    _Var4 = std::codecvt<char,char,struct__Mbstatet>::_Getcat((facet **)&local_28,param_1);
    plVar3 = local_28;
    if (_Var4 == 0xffffffffffffffff) {
      FUN_1400011e0();
      pcVar2 = (code *)swi(3);
      (*pcVar2)();
      return;
    }
    local_18 = local_28;
    std::_Facet_Register((_Facet_base *)local_28);
    (**(code **)(*plVar3 + 8))(plVar3);
    DAT_14000a8b8 = local_28;
  }
LAB_140003eba:
  std::_Lockit::__Lockit(local_20);
  FUN_1400047b0(local_10 ^ (ulonglong)auStack72);
  return;
}



void ** FUN_140003ef0(void **param_1,undefined8 param_2,undefined8 param_3,undefined param_4)

{
  void *pvVar1;
  code *pcVar2;
  void *pvVar3;
  void **ppvVar4;
  void *pvVar5;
  ulonglong uVar6;
  void *pvVar7;
  void *pvVar8;
  
  pvVar8 = param_1[2];
  if (pvVar8 == (void *)0x7fffffffffffffff) {
    FUN_140004200();
    pcVar2 = (code *)swi(3);
    ppvVar4 = (void **)(*pcVar2)();
    return ppvVar4;
  }
  pvVar1 = param_1[3];
  pvVar5 = (void *)((ulonglong)(void *)((longlong)pvVar8 + 1U) | 0xf);
  pvVar7 = (void *)0x7fffffffffffffff;
  if (((pvVar5 < (void *)0x8000000000000000) &&
      (pvVar1 <= (void *)(0x7fffffffffffffff - ((ulonglong)pvVar1 >> 1)))) &&
     (pvVar3 = (void *)(((ulonglong)pvVar1 >> 1) + (longlong)pvVar1), pvVar7 = pvVar5,
     pvVar5 < pvVar3)) {
    pvVar7 = pvVar3;
  }
  uVar6 = (longlong)pvVar7 + 1;
  if (pvVar7 == (void *)0xffffffffffffffff) {
    uVar6 = 0xffffffffffffffff;
  }
  if (uVar6 < 0x1000) {
    if (uVar6 == 0) {
      pvVar5 = (void *)0x0;
    }
    else {
      pvVar5 = operator_new(uVar6);
    }
  }
  else {
    if (uVar6 + 0x27 <= uVar6) {
      FUN_140001110();
      pcVar2 = (code *)swi(3);
      ppvVar4 = (void **)(*pcVar2)();
      return ppvVar4;
    }
    pvVar3 = operator_new(uVar6 + 0x27);
    if (pvVar3 == (void *)0x0) goto LAB_14000400c;
    pvVar5 = (void *)((longlong)pvVar3 + 0x27U & 0xffffffffffffffe0);
    *(void **)((longlong)pvVar5 - 8) = pvVar3;
  }
  param_1[2] = (void *)((longlong)pvVar8 + 1U);
  param_1[3] = pvVar7;
  if (pvVar1 < (void *)0x10) {
    memcpy(pvVar5,param_1,(size_t)pvVar8);
    *(undefined *)((longlong)pvVar5 + (longlong)pvVar8) = param_4;
    *(undefined *)((longlong)pvVar5 + 1 + (longlong)pvVar8) = 0;
  }
  else {
    pvVar7 = *param_1;
    memcpy(pvVar5,pvVar7,(size_t)pvVar8);
    *(undefined *)((longlong)pvVar5 + (longlong)pvVar8) = param_4;
    *(undefined *)((longlong)pvVar5 + 1 + (longlong)pvVar8) = 0;
    pvVar8 = pvVar7;
    if ((0xfff < (longlong)pvVar1 + 1U) &&
       (pvVar8 = *(void **)((longlong)pvVar7 + -8),
       0x1f < (ulonglong)((longlong)pvVar7 + (-8 - (longlong)pvVar8)))) {
LAB_14000400c:
      _invalid_parameter_noinfo_noreturn();
      pcVar2 = (code *)swi(3);
      ppvVar4 = (void **)(*pcVar2)();
      return ppvVar4;
    }
    free(pvVar8);
  }
  *param_1 = pvVar5;
  return param_1;
}



void ** FUN_140004050(void **param_1,ulonglong param_2,undefined8 param_3,void *param_4,
                     size_t param_5)

{
  void *pvVar1;
  code *pcVar2;
  void *pvVar3;
  void **ppvVar4;
  void *pvVar5;
  ulonglong uVar6;
  void *pvVar7;
  void *pvVar8;
  
  pvVar8 = param_1[2];
  if (0x7fffffffffffffffU - (longlong)pvVar8 < param_2) {
    FUN_140004200();
    pcVar2 = (code *)swi(3);
    ppvVar4 = (void **)(*pcVar2)();
    return ppvVar4;
  }
  pvVar1 = param_1[3];
  pvVar5 = (void *)((ulonglong)(void *)(param_2 + (longlong)pvVar8) | 0xf);
  pvVar7 = (void *)0x7fffffffffffffff;
  if (((pvVar5 < (void *)0x8000000000000000) &&
      (pvVar1 <= (void *)(0x7fffffffffffffff - ((ulonglong)pvVar1 >> 1)))) &&
     (pvVar3 = (void *)(((ulonglong)pvVar1 >> 1) + (longlong)pvVar1), pvVar7 = pvVar5,
     pvVar5 < pvVar3)) {
    pvVar7 = pvVar3;
  }
  uVar6 = (longlong)pvVar7 + 1;
  if (pvVar7 == (void *)0xffffffffffffffff) {
    uVar6 = 0xffffffffffffffff;
  }
  if (uVar6 < 0x1000) {
    if (uVar6 == 0) {
      pvVar5 = (void *)0x0;
    }
    else {
      pvVar5 = operator_new(uVar6);
    }
  }
  else {
    if (uVar6 + 0x27 <= uVar6) {
      FUN_140001110();
      pcVar2 = (code *)swi(3);
      ppvVar4 = (void **)(*pcVar2)();
      return ppvVar4;
    }
    pvVar3 = operator_new(uVar6 + 0x27);
    if (pvVar3 == (void *)0x0) goto LAB_14000418a;
    pvVar5 = (void *)((longlong)pvVar3 + 0x27U & 0xffffffffffffffe0);
    *(void **)((longlong)pvVar5 - 8) = pvVar3;
  }
  param_1[2] = (void *)(param_2 + (longlong)pvVar8);
  pvVar3 = (void *)((longlong)pvVar5 + (longlong)pvVar8);
  param_1[3] = pvVar7;
  if (pvVar1 < (void *)0x10) {
    memcpy(pvVar5,param_1,(size_t)pvVar8);
    memcpy(pvVar3,param_4,param_5);
    *(undefined *)((longlong)pvVar3 + param_5) = 0;
  }
  else {
    pvVar7 = *param_1;
    memcpy(pvVar5,pvVar7,(size_t)pvVar8);
    memcpy(pvVar3,param_4,param_5);
    *(undefined *)((longlong)pvVar3 + param_5) = 0;
    pvVar8 = pvVar7;
    if ((0xfff < (longlong)pvVar1 + 1U) &&
       (pvVar8 = *(void **)((longlong)pvVar7 + -8),
       0x1f < (ulonglong)((longlong)pvVar7 + (-8 - (longlong)pvVar8)))) {
LAB_14000418a:
      _invalid_parameter_noinfo_noreturn();
      pcVar2 = (code *)swi(3);
      ppvVar4 = (void **)(*pcVar2)();
      return ppvVar4;
    }
    free(pvVar8);
  }
  *param_1 = pvVar5;
  return param_1;
}



void FUN_140004200(void)

{
  code *pcVar1;
  
  std::_Xlength_error("string too long");
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



longlong * FUN_140004220(longlong *param_1,void **param_2)

{
  longlong *plVar1;
  void *pvVar2;
  void *pvVar3;
  bool bVar4;
  bool bVar5;
  locale lVar6;
  uint uVar7;
  undefined7 extraout_var;
  longlong lVar8;
  code **ppcVar9;
  void **ppvVar10;
  uint uVar11;
  ulonglong uVar12;
  longlong *local_30;
  
  bVar4 = false;
  plVar1 = *(longlong **)((longlong)*(int *)(*param_1 + 4) + 0x48 + (longlong)param_1);
  if (plVar1 != (longlong *)0x0) {
    (**(code **)(*plVar1 + 8))();
  }
  bVar5 = std::basic_istream<char,struct_std::char_traits<char>_>::_Ipfx
                    ((basic_istream_char_struct_std__char_traits_char___ *)param_1,false);
  uVar11 = 0;
  if (bVar5 != false) {
    lVar6 = std::ios_base::getloc
                      ((ios_base *)((longlong)*(int *)(*param_1 + 4) + (longlong)param_1));
    lVar8 = FUN_1400038c0((locale *)CONCAT71(extraout_var,lVar6));
    if ((local_30 != (longlong *)0x0) &&
       (ppcVar9 = (code **)(**(code **)(*local_30 + 0x10))(), ppcVar9 != (code **)0x0)) {
      (**(code **)*ppcVar9)(ppcVar9);
    }
    param_2[2] = (void *)0x0;
    ppvVar10 = param_2;
    if ((void *)0xf < param_2[3]) {
      ppvVar10 = (void **)*param_2;
    }
    *(undefined *)ppvVar10 = 0;
    uVar12 = *(ulonglong *)((longlong)*(int *)(*param_1 + 4) + 0x28 + (longlong)param_1);
    if (((longlong)uVar12 < 1) || (0x7ffffffffffffffe < uVar12)) {
      uVar12 = 0x7fffffffffffffff;
    }
    uVar7 = std::basic_streambuf<char,struct_std::char_traits<char>_>::sgetc
                      (*(basic_streambuf_char_struct_std__char_traits_char___ **)
                        ((longlong)*(int *)(*param_1 + 4) + 0x48 + (longlong)param_1));
    while (uVar11 = 0, uVar12 != 0) {
      if (uVar7 == 0xffffffff) {
        uVar11 = 1;
        break;
      }
      uVar7 = uVar7 & 0xff;
      uVar11 = 0;
      if ((*(byte *)(*(longlong *)(lVar8 + 0x18) + (ulonglong)uVar7 * 2) & 0x48) != 0) break;
      pvVar2 = param_2[2];
      pvVar3 = param_2[3];
      if (pvVar2 < pvVar3) {
        param_2[2] = (void *)((longlong)pvVar2 + 1);
        ppvVar10 = param_2;
        if ((void *)0xf < pvVar3) {
          ppvVar10 = (void **)*param_2;
        }
        *(char *)((longlong)ppvVar10 + (longlong)pvVar2) = (char)uVar7;
        *(undefined *)((longlong)ppvVar10 + 1 + (longlong)pvVar2) = 0;
      }
      else {
        FUN_140003ef0(param_2,pvVar3,(ulonglong)uVar7,(char)uVar7);
      }
      bVar4 = true;
      uVar12 = uVar12 - 1;
      uVar7 = std::basic_streambuf<char,struct_std::char_traits<char>_>::snextc
                        (*(basic_streambuf_char_struct_std__char_traits_char___ **)
                          ((longlong)*(int *)(*param_1 + 4) + 0x48 + (longlong)param_1));
    }
  }
  *(undefined8 *)((longlong)*(int *)(*param_1 + 4) + 0x28 + (longlong)param_1) = 0;
  if (!bVar4) {
    uVar11 = uVar11 | 2;
  }
  std::basic_ios<char,struct_std::char_traits<char>_>::setstate
            ((basic_ios_char_struct_std__char_traits_char___ *)
             ((longlong)*(int *)(*param_1 + 4) + (longlong)param_1),uVar11,false);
  plVar1 = *(longlong **)((longlong)*(int *)(*param_1 + 4) + 0x48 + (longlong)param_1);
  if (plVar1 != (longlong *)0x0) {
    (**(code **)(*plVar1 + 0x10))();
  }
  return param_1;
}



longlong * FUN_140004410(longlong *param_1,char *param_2,ulonglong param_3)

{
  longlong *plVar1;
  bool bVar2;
  int iVar3;
  ulonglong uVar4;
  longlong lVar5;
  int iVar6;
  longlong lVar7;
  
  iVar6 = 0;
  lVar5 = *param_1;
  uVar4 = *(ulonglong *)((longlong)*(int *)(lVar5 + 4) + 0x28 + (longlong)param_1);
  if (((longlong)uVar4 < 1) || (uVar4 <= param_3)) {
    lVar7 = 0;
  }
  else {
    lVar7 = uVar4 - param_3;
  }
  plVar1 = *(longlong **)((longlong)*(int *)(lVar5 + 4) + 0x48 + (longlong)param_1);
  if (plVar1 != (longlong *)0x0) {
    (**(code **)(*plVar1 + 8))(plVar1);
    lVar5 = *param_1;
  }
  if (*(int *)((longlong)*(int *)(lVar5 + 4) + 0x10 + (longlong)param_1) == 0) {
    plVar1 = *(longlong **)((longlong)*(int *)(lVar5 + 4) + 0x50 + (longlong)param_1);
    if ((plVar1 == (longlong *)0x0) || (plVar1 == param_1)) {
      bVar2 = true;
    }
    else {
      std::basic_ostream<char,struct_std::char_traits<char>_>::flush
                ((basic_ostream_char_struct_std__char_traits_char___ *)plVar1);
      lVar5 = *param_1;
      bVar2 = *(int *)((longlong)*(int *)(lVar5 + 4) + 0x10 + (longlong)param_1) == 0;
    }
  }
  else {
    bVar2 = false;
  }
  if (bVar2) {
    if ((*(uint *)((longlong)*(int *)(lVar5 + 4) + 0x18 + (longlong)param_1) & 0x1c0) != 0x40) {
      while (lVar7 != 0) {
        iVar3 = std::basic_streambuf<char,struct_std::char_traits<char>_>::sputc
                          (*(basic_streambuf_char_struct_std__char_traits_char___ **)
                            ((longlong)*(int *)(*param_1 + 4) + 0x48 + (longlong)param_1),
                           *(char *)((longlong)*(int *)(*param_1 + 4) + 0x58 + (longlong)param_1));
        if (iVar3 == -1) {
          iVar6 = 4;
          goto LAB_140004502;
        }
        lVar7 = lVar7 + -1;
      }
      lVar5 = *param_1;
    }
    uVar4 = std::basic_streambuf<char,struct_std::char_traits<char>_>::sputn
                      (*(basic_streambuf_char_struct_std__char_traits_char___ **)
                        ((longlong)*(int *)(lVar5 + 4) + 0x48 + (longlong)param_1),param_2,param_3);
    if (uVar4 == param_3) {
LAB_140004502:
      do {
        if (lVar7 == 0) goto LAB_14000452a;
        iVar3 = std::basic_streambuf<char,struct_std::char_traits<char>_>::sputc
                          (*(basic_streambuf_char_struct_std__char_traits_char___ **)
                            ((longlong)*(int *)(*param_1 + 4) + 0x48 + (longlong)param_1),
                           *(char *)((longlong)*(int *)(*param_1 + 4) + 0x58 + (longlong)param_1));
        if (iVar3 == -1) break;
        lVar7 = lVar7 + -1;
      } while( true );
    }
    iVar6 = 4;
LAB_14000452a:
    *(undefined8 *)((longlong)*(int *)(*param_1 + 4) + 0x28 + (longlong)param_1) = 0;
  }
  else {
    iVar6 = 4;
  }
  std::basic_ios<char,struct_std::char_traits<char>_>::setstate
            ((basic_ios_char_struct_std__char_traits_char___ *)
             ((longlong)*(int *)(*param_1 + 4) + (longlong)param_1),iVar6,false);
  bVar2 = std::uncaught_exception();
  if (bVar2 == false) {
    std::basic_ostream<char,struct_std::char_traits<char>_>::_Osfx
              ((basic_ostream_char_struct_std__char_traits_char___ *)param_1);
  }
  plVar1 = *(longlong **)((longlong)*(int *)(*param_1 + 4) + 0x48 + (longlong)param_1);
  if (plVar1 != (longlong *)0x0) {
    (**(code **)(*plVar1 + 0x10))();
  }
  return param_1;
}



void ** FUN_1400045d0(void **param_1,ulonglong param_2)

{
  void *pvVar1;
  code *pcVar2;
  void *pvVar3;
  void **ppvVar4;
  ulonglong uVar5;
  void *pvVar6;
  void *pvVar7;
  void *pvVar8;
  
  pvVar8 = param_1[2];
  if (0x7fffffffffffffffU - (longlong)pvVar8 < param_2) {
    FUN_140004200();
    pcVar2 = (code *)swi(3);
    ppvVar4 = (void **)(*pcVar2)();
    return ppvVar4;
  }
  pvVar1 = param_1[3];
  pvVar6 = (void *)((ulonglong)(void *)(param_2 + (longlong)pvVar8) | 0xf);
  pvVar7 = (void *)0x7fffffffffffffff;
  if (((pvVar6 < (void *)0x8000000000000000) &&
      (pvVar1 <= (void *)(0x7fffffffffffffff - ((ulonglong)pvVar1 >> 1)))) &&
     (pvVar3 = (void *)(((ulonglong)pvVar1 >> 1) + (longlong)pvVar1), pvVar7 = pvVar6,
     pvVar6 < pvVar3)) {
    pvVar7 = pvVar3;
  }
  uVar5 = (longlong)pvVar7 + 1;
  if (pvVar7 == (void *)0xffffffffffffffff) {
    uVar5 = 0xffffffffffffffff;
  }
  if (uVar5 < 0x1000) {
    if (uVar5 == 0) {
      pvVar6 = (void *)0x0;
    }
    else {
      pvVar6 = operator_new(uVar5);
    }
  }
  else {
    if (uVar5 + 0x27 <= uVar5) {
      FUN_140001110();
      pcVar2 = (code *)swi(3);
      ppvVar4 = (void **)(*pcVar2)();
      return ppvVar4;
    }
    pvVar3 = operator_new(uVar5 + 0x27);
    if (pvVar3 == (void *)0x0) goto LAB_1400046de;
    pvVar6 = (void *)((longlong)pvVar3 + 0x27U & 0xffffffffffffffe0);
    *(void **)((longlong)pvVar6 - 8) = pvVar3;
  }
  param_1[2] = (void *)(param_2 + (longlong)pvVar8);
  param_1[3] = pvVar7;
  if (pvVar1 < (void *)0x10) {
    memcpy(pvVar6,param_1,(longlong)pvVar8 + 1U);
  }
  else {
    pvVar7 = *param_1;
    memcpy(pvVar6,pvVar7,(longlong)pvVar8 + 1U);
    pvVar8 = pvVar7;
    if ((0xfff < (longlong)pvVar1 + 1U) &&
       (pvVar8 = *(void **)((longlong)pvVar7 + -8),
       0x1f < (ulonglong)((longlong)pvVar7 + (-8 - (longlong)pvVar8)))) {
LAB_1400046de:
      _invalid_parameter_noinfo_noreturn();
      pcVar2 = (code *)swi(3);
      ppvVar4 = (void **)(*pcVar2)();
      return ppvVar4;
    }
    free(pvVar8);
  }
  *param_1 = pvVar6;
  return param_1;
}



void FUN_140004720(longlong **param_1)

{
  longlong *plVar1;
  
  plVar1 = *(longlong **)((longlong)*(int *)(**param_1 + 4) + 0x48 + (longlong)*param_1);
  if (plVar1 != (longlong *)0x0) {
    (**(code **)(*plVar1 + 0x10))();
  }
  return;
}



void FUN_140004744(longlong param_1,uint param_2)

{
  FUN_1400034c0(param_1 - *(int *)(param_1 + -4),param_2);
  return;
}



// WARNING: Unknown calling convention yet parameter storage is locked
// Library Function - Single Match
//  void __cdecl std::_Facet_Register(class std::_Facet_base * __ptr64)
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void std::_Facet_Register(_Facet_base *param_1)

{
  undefined8 *puVar1;
  
  puVar1 = (undefined8 *)operator_new(0x10);
  if (puVar1 != (undefined8 *)0x0) {
    *puVar1 = DAT_14000a2d0;
    puVar1[1] = param_1;
  }
  DAT_14000a2d0 = puVar1;
  return;
}



// WARNING: Exceeded maximum restarts with more pending

__int64 __thiscall
std::basic_streambuf<char,struct_std::char_traits<char>_>::showmanyc
          (basic_streambuf_char_struct_std__char_traits_char___ *this)

{
  __int64 _Var1;
  
                    // WARNING: Could not recover jumptable at 0x000140004796. Too many branches
                    // WARNING: Treating indirect jump as call
  _Var1 = showmanyc();
  return _Var1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_1400047b0(longlong param_1)

{
  code *pcVar1;
  BOOL BVar2;
  undefined *puVar3;
  undefined auStack56 [8];
  undefined auStack48 [48];
  
  if ((param_1 == DAT_14000a010) && ((short)((ulonglong)param_1 >> 0x30) == 0)) {
    return;
  }
  puVar3 = auStack56;
  BVar2 = IsProcessorFeaturePresent(0x17);
  if (BVar2 != 0) {
    pcVar1 = (code *)swi(0x29);
    (*pcVar1)(2);
    puVar3 = auStack48;
  }
  *(undefined8 *)(puVar3 + -8) = 0x140004d6a;
  capture_previous_context((PCONTEXT)&DAT_14000a3c0,puVar3[-8]);
  _DAT_14000a330 = *(undefined8 *)(puVar3 + 0x38);
  _DAT_14000a458 = puVar3 + 0x40;
  _DAT_14000a440 = *(undefined8 *)(puVar3 + 0x40);
  _DAT_14000a320 = 0xc0000409;
  _DAT_14000a324 = 1;
  _DAT_14000a338 = 1;
  DAT_14000a340 = 2;
  *(longlong *)(puVar3 + 0x20) = DAT_14000a010;
  *(undefined8 *)(puVar3 + 0x28) = DAT_14000a008;
  *(undefined8 *)(puVar3 + -8) = 0x140004e0c;
  DAT_14000a4b8 = _DAT_14000a330;
  __raise_securityfailure((_EXCEPTION_POINTERS *)&PTR_DAT_140006490,puVar3[-8]);
  return;
}



// Library Function - Single Match
//  void * __ptr64 __cdecl operator new(unsigned __int64)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void * operator_new(__uint64 param_1)

{
  code *pcVar1;
  int iVar2;
  void *pvVar3;
  
  do {
    pvVar3 = malloc(param_1);
    if (pvVar3 != (void *)0x0) {
      return pvVar3;
    }
    iVar2 = _callnewh(param_1);
  } while (iVar2 != 0);
  if (param_1 == 0xffffffffffffffff) {
    FUN_140001110();
    pcVar1 = (code *)swi(3);
    pvVar3 = (void *)(*pcVar1)();
    return pvVar3;
  }
  FUN_140004ea8();
  pcVar1 = (code *)swi(3);
  pvVar3 = (void *)(*pcVar1)();
  return pvVar3;
}



void free(void *_Memory)

{
  free(_Memory);
  return;
}



undefined ** FUN_140004818(undefined **param_1,ulonglong param_2)

{
  *param_1 = (undefined *)type_info::vftable;
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



void FUN_140004844(void)

{
  code *pcVar1;
  bool bVar2;
  char cVar3;
  int iVar4;
  undefined8 uVar5;
  undefined4 *puVar6;
  undefined7 extraout_var;
  
  _set_app_type();
  uVar5 = FUN_140004f88();
  _set_fmode((int)uVar5);
  uVar5 = FUN_140004f7c();
  puVar6 = (undefined4 *)__p__commode();
  *puVar6 = (int)uVar5;
  uVar5 = __scrt_initialize_onexit_tables(1);
  if ((char)uVar5 != '\0') {
    FUN_140005208();
    atexit(&LAB_140005244);
    FUN_140004f80();
    iVar4 = _configure_narrow_argv();
    if (iVar4 == 0) {
      FUN_140004f90();
      bVar2 = FUN_140004fd0();
      if ((int)CONCAT71(extraout_var,bVar2) != 0) {
        __setusermatherr();
      }
      _guard_check_icall();
      _guard_check_icall();
      uVar5 = FUN_140004f7c();
      _configthreadlocale((int)uVar5);
      cVar3 = FUN_140004fa0();
      if (cVar3 != '\0') {
        _initialize_narrow_environment();
      }
      FUN_140004f7c();
      uVar5 = thunk_FUN_140004f7c();
      if ((int)uVar5 == 0) {
        return;
      }
    }
  }
  __scrt_fastfail(7);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



undefined8 FUN_1400048fc(void)

{
  FUN_140004fb4();
  return 0;
}



// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall

ulonglong entry(void)

{
  bool bVar1;
  int iVar2;
  ulonglong uVar3;
  code **ppcVar4;
  longlong *plVar5;
  uint *puVar6;
  ulonglong uVar7;
  ulonglong uVar8;
  uint unaff_EBX;
  
  __security_init_cookie();
  uVar3 = __scrt_initialize_crt(1);
  if ((char)uVar3 == '\0') {
    __scrt_fastfail(7);
  }
  else {
    bVar1 = false;
    uVar3 = __scrt_acquire_startup_lock();
    unaff_EBX = unaff_EBX & 0xffffff00 | (uint)(uVar3 & 0xff);
    if (DAT_14000a2d8 != 1) {
      if (DAT_14000a2d8 == 0) {
        DAT_14000a2d8 = 1;
        iVar2 = _initterm_e(&DAT_140006418,&DAT_140006430);
        if (iVar2 != 0) {
          return 0xff;
        }
        _initterm(&DAT_1400063f8,&DAT_140006410);
        DAT_14000a2d8 = 2;
      }
      else {
        bVar1 = true;
      }
      __scrt_release_startup_lock((char)(uVar3 & 0xff));
      ppcVar4 = (code **)FUN_140004fdc();
      if ((*ppcVar4 != (code *)0x0) &&
         (uVar3 = FUN_140004bcc((longlong)ppcVar4), (char)uVar3 != '\0')) {
        (**ppcVar4)();
      }
      plVar5 = (longlong *)FUN_140004fe4();
      if ((*plVar5 != 0) && (uVar3 = FUN_140004bcc((longlong)plVar5), (char)uVar3 != '\0')) {
        _register_thread_local_exe_atexit_callback();
      }
      _get_initial_narrow_environment();
      __p___argv();
      puVar6 = (uint *)__p___argc();
      uVar8 = (ulonglong)*puVar6;
      uVar3 = FUN_140002490();
      unaff_EBX = (uint)(uVar3 & 0xffffffff);
      uVar7 = __scrt_is_managed_app();
      if ((char)uVar7 != '\0') {
        if (!bVar1) {
          _cexit();
        }
        __scrt_uninitialize_crt(CONCAT71((int7)(uVar8 >> 8),1),'\0');
        return uVar3 & 0xffffffff;
      }
      goto LAB_140004a94;
    }
  }
  __scrt_fastfail(7);
LAB_140004a94:
                    // WARNING: Subroutine does not return
  exit(unaff_EBX);
}



// Library Function - Single Match
//  __scrt_acquire_startup_lock
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

ulonglong __scrt_acquire_startup_lock(void)

{
  ulonglong uVar1;
  bool bVar2;
  undefined7 extraout_var;
  longlong in_GS_OFFSET;
  ulonglong uVar3;
  
  bVar2 = __scrt_is_ucrt_dll_in_use();
  uVar3 = CONCAT71(extraout_var,bVar2);
  if ((int)uVar3 == 0) {
LAB_140004ae6:
    uVar3 = uVar3 & 0xffffffffffffff00;
  }
  else {
    uVar1 = *(ulonglong *)(*(longlong *)(in_GS_OFFSET + 0x30) + 8);
    do {
      LOCK();
      bVar2 = DAT_14000a2e0 == 0;
      DAT_14000a2e0 = DAT_14000a2e0 ^ (ulonglong)bVar2 * (DAT_14000a2e0 ^ uVar1);
      uVar3 = !bVar2 * DAT_14000a2e0;
      if (bVar2) goto LAB_140004ae6;
    } while (uVar1 != uVar3);
    uVar3 = CONCAT71((int7)(uVar3 >> 8),1);
  }
  return uVar3;
}



// Library Function - Single Match
//  __scrt_initialize_crt
// 
// Library: Visual Studio 2019 Release

ulonglong __scrt_initialize_crt(int param_1)

{
  ulonglong uVar1;
  
  if (param_1 == 0) {
    DAT_14000a2e8 = 1;
  }
  __isa_available_init();
  uVar1 = FUN_140004fa0();
  if ((char)uVar1 != '\0') {
    uVar1 = FUN_140004fa0();
    if ((char)uVar1 != '\0') {
      return uVar1 & 0xffffffffffffff00 | 1;
    }
    uVar1 = FUN_140004fa0();
  }
  return uVar1 & 0xffffffffffffff00;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __scrt_initialize_onexit_tables
// 
// Library: Visual Studio 2019 Release

ulonglong __scrt_initialize_onexit_tables(uint param_1)

{
  code *pcVar1;
  bool bVar2;
  ulonglong in_RAX;
  undefined7 extraout_var;
  ulonglong uVar3;
  
  if (DAT_14000a2e9 == '\0') {
    if (1 < param_1) {
      __scrt_fastfail(5);
      pcVar1 = (code *)swi(3);
      uVar3 = (*pcVar1)();
      return uVar3;
    }
    bVar2 = __scrt_is_ucrt_dll_in_use();
    if (((int)CONCAT71(extraout_var,bVar2) == 0) || (param_1 != 0)) {
      in_RAX = 0xffffffffffffffff;
      _DAT_14000a2f0 = 0xffffffff;
      uRam000000014000a2f4 = 0xffffffff;
      uRam000000014000a2f8 = 0xffffffff;
      uRam000000014000a2fc = 0xffffffff;
      _DAT_14000a300 = 0xffffffffffffffff;
      _DAT_14000a308 = 0xffffffff;
      uRam000000014000a30c = 0xffffffff;
      uRam000000014000a310 = 0xffffffff;
      uRam000000014000a314 = 0xffffffff;
      _DAT_14000a318 = 0xffffffffffffffff;
    }
    else {
      in_RAX = _initialize_onexit_table(&DAT_14000a2f0);
      if (((int)in_RAX != 0) ||
         (in_RAX = _initialize_onexit_table(&DAT_14000a308), (int)in_RAX != 0)) {
        return in_RAX & 0xffffffffffffff00;
      }
    }
    DAT_14000a2e9 = '\x01';
  }
  return CONCAT71((int7)(in_RAX >> 8),1);
}



// WARNING: Removing unreachable block (ram,0x000140004c57)

ulonglong FUN_140004bcc(longlong param_1)

{
  uint uVar1;
  uint7 uVar3;
  IMAGE_SECTION_HEADER *pIVar4;
  ulonglong uVar2;
  
  pIVar4 = &IMAGE_SECTION_HEADER_140000200;
  uVar2 = 0;
  do {
    if (pIVar4 == (IMAGE_SECTION_HEADER *)&DAT_1400002f0) {
LAB_140004c53:
      return uVar2 & 0xffffffffffffff00;
    }
    if ((ulonglong)(uint)pIVar4->VirtualAddress <= param_1 - 0x140000000U) {
      uVar1 = pIVar4->Misc + pIVar4->VirtualAddress;
      uVar2 = (ulonglong)uVar1;
      if (param_1 - 0x140000000U < uVar2) {
        if (pIVar4 != (IMAGE_SECTION_HEADER *)0x0) {
          uVar3 = (uint7)(uint3)(uVar1 >> 8);
          if ((int)pIVar4->Characteristics < 0) {
            return (ulonglong)uVar3 << 8;
          }
          return CONCAT71(uVar3,1);
        }
        goto LAB_140004c53;
      }
    }
    pIVar4 = pIVar4 + 1;
  } while( true );
}



// Library Function - Single Match
//  __scrt_release_startup_lock
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __scrt_release_startup_lock(char param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  
  bVar1 = __scrt_is_ucrt_dll_in_use();
  if ((CONCAT31(extraout_var,bVar1) != 0) && (param_1 == '\0')) {
    DAT_14000a2e0 = 0;
  }
  return;
}



// Library Function - Single Match
//  __scrt_uninitialize_crt
// 
// Library: Visual Studio 2019 Release

undefined __scrt_uninitialize_crt(undefined8 param_1,char param_2)

{
  if ((DAT_14000a2e8 == '\0') || (param_2 == '\0')) {
    FUN_140004fa0();
    FUN_140004fa0();
  }
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  _onexit
// 
// Library: Visual Studio 2019 Release

_onexit_t _onexit(_onexit_t _Func)

{
  int iVar1;
  _onexit_t p_Var2;
  
  if (_DAT_14000a2f0 == -1) {
    iVar1 = _crt_atexit();
  }
  else {
    iVar1 = _register_onexit_function(&DAT_14000a2f0);
  }
  p_Var2 = (_onexit_t)0x0;
  if (iVar1 == 0) {
    p_Var2 = _Func;
  }
  return p_Var2;
}



// Library Function - Single Match
//  atexit
// 
// Library: Visual Studio 2019 Release

int atexit(void *param_1)

{
  _onexit_t p_Var1;
  
  p_Var1 = _onexit((_onexit_t)param_1);
  return (int)((p_Var1 != (_onexit_t)0x0) - 1);
}



void _guard_check_icall(void)

{
  return;
}



// Library Function - Single Match
//  __raise_securityfailure
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __raise_securityfailure(_EXCEPTION_POINTERS *param_1)

{
  HANDLE hProcess;
  
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  UnhandledExceptionFilter(param_1);
  hProcess = GetCurrentProcess();
                    // WARNING: Could not recover jumptable at 0x000140004d39. Too many branches
                    // WARNING: Treating indirect jump as call
  TerminateProcess(hProcess,0xc0000409);
  return;
}



// Library Function - Single Match
//  capture_previous_context
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void capture_previous_context(PCONTEXT param_1)

{
  DWORD64 ControlPc;
  PRUNTIME_FUNCTION FunctionEntry;
  int iVar1;
  DWORD64 local_res8;
  ulonglong local_res10;
  PVOID local_res18 [2];
  
  RtlCaptureContext();
  ControlPc = param_1->Rip;
  iVar1 = 0;
  do {
    FunctionEntry = RtlLookupFunctionEntry(ControlPc,&local_res8,(PUNWIND_HISTORY_TABLE)0x0);
    if (FunctionEntry == (PRUNTIME_FUNCTION)0x0) {
      return;
    }
    RtlVirtualUnwind(0,local_res8,ControlPc,FunctionEntry,param_1,local_res18,&local_res10,
                     (PKNONVOLATILE_CONTEXT_POINTERS)0x0);
    iVar1 = iVar1 + 1;
  } while (iVar1 < 2);
  return;
}



undefined ** FUN_140004e88(undefined **param_1)

{
  param_1[2] = (undefined *)0x0;
  param_1[1] = "bad allocation";
  *param_1 = (undefined *)std::bad_alloc::vftable;
  return param_1;
}



void FUN_140004ea8(void)

{
  undefined *local_28 [5];
  
  FUN_140004e88(local_28);
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_28,(ThrowInfo *)&DAT_140007ea8);
}



void free(void *_Memory)

{
                    // WARNING: Could not recover jumptable at 0x0001400054ea. Too many branches
                    // WARNING: Treating indirect jump as call
  free(_Memory);
  return;
}



// Library Function - Single Match
//  __security_init_cookie
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __security_init_cookie(void)

{
  DWORD DVar1;
  _FILETIME local_res8;
  _FILETIME local_res10;
  uint local_res18;
  undefined4 uStackX28;
  
  if (DAT_14000a010 == 0x2b992ddfa232) {
    local_res10 = (_FILETIME)0x0;
    GetSystemTimeAsFileTime((LPFILETIME)&local_res10);
    local_res8 = local_res10;
    DVar1 = GetCurrentThreadId();
    local_res8 = (_FILETIME)((ulonglong)local_res8 ^ (ulonglong)DVar1);
    DVar1 = GetCurrentProcessId();
    local_res8 = (_FILETIME)((ulonglong)local_res8 ^ (ulonglong)DVar1);
    QueryPerformanceCounter((LARGE_INTEGER *)&local_res18);
    DAT_14000a010 =
         ((ulonglong)local_res18 << 0x20 ^ CONCAT44(uStackX28,local_res18) ^ (ulonglong)local_res8 ^
         (ulonglong)&local_res8) & 0xffffffffffff;
    if (DAT_14000a010 == 0x2b992ddfa232) {
      DAT_14000a010 = 0x2b992ddfa233;
    }
  }
  DAT_14000a008 = ~DAT_14000a010;
  return;
}



undefined8 FUN_140004f7c(void)

{
  return 0;
}



undefined8 FUN_140004f80(void)

{
  return 1;
}



undefined8 FUN_140004f88(void)

{
  return 0x4000;
}



void FUN_140004f90(void)

{
                    // WARNING: Could not recover jumptable at 0x000140004f97. Too many branches
                    // WARNING: Treating indirect jump as call
  InitializeSListHead((PSLIST_HEADER)&DAT_14000a890);
  return;
}



undefined FUN_140004fa0(void)

{
  return 1;
}



undefined * FUN_140004fa4(void)

{
  return &DAT_14000a8a0;
}



undefined * FUN_140004fac(void)

{
  return &DAT_14000a8a8;
}



void FUN_140004fb4(void)

{
  ulonglong *puVar1;
  
  puVar1 = (ulonglong *)FUN_140004fa4();
  *puVar1 = *puVar1 | 0x24;
  puVar1 = (ulonglong *)FUN_140004fac();
  *puVar1 = *puVar1 | 2;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

bool FUN_140004fd0(void)

{
  return _DAT_14000a018 == 0;
}



undefined * FUN_140004fdc(void)

{
  return &DAT_14000a8d8;
}



undefined * FUN_140004fe4(void)

{
  return &DAT_14000a8d0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_140004fec(void)

{
  _DAT_14000a8b0 = 0;
  return;
}



// Library Function - Single Match
//  __scrt_fastfail
// 
// Library: Visual Studio 2019 Release

void __scrt_fastfail(undefined4 param_1)

{
  code *pcVar1;
  BOOL BVar2;
  LONG LVar3;
  PRUNTIME_FUNCTION FunctionEntry;
  undefined *puVar4;
  undefined8 in_stack_00000000;
  DWORD64 local_res10;
  undefined local_res18 [8];
  undefined local_res20 [8];
  undefined auStack1480 [8];
  undefined auStack1472 [232];
  undefined local_4d8 [152];
  undefined *local_440;
  DWORD64 local_3e0;
  
  puVar4 = auStack1480;
  BVar2 = IsProcessorFeaturePresent(0x17);
  if (BVar2 != 0) {
    pcVar1 = (code *)swi(0x29);
    (*pcVar1)(param_1);
    puVar4 = auStack1472;
  }
  *(undefined8 *)(puVar4 + -8) = 0x140005027;
  FUN_140004fec(puVar4[-8]);
  *(undefined8 *)(puVar4 + -8) = 0x140005038;
  memset(local_4d8,0,0x4d0,puVar4[-8]);
  *(undefined8 *)(puVar4 + -8) = 0x140005042;
  RtlCaptureContext(local_4d8);
  *(undefined8 *)(puVar4 + -8) = 0x14000505c;
  FunctionEntry =
       RtlLookupFunctionEntry(local_3e0,&local_res10,(PUNWIND_HISTORY_TABLE)0x0,puVar4[-8]);
  if (FunctionEntry != (PRUNTIME_FUNCTION)0x0) {
    *(undefined8 *)(puVar4 + 0x38) = 0;
    *(undefined **)(puVar4 + 0x30) = local_res18;
    *(undefined **)(puVar4 + 0x28) = local_res20;
    *(undefined **)(puVar4 + 0x20) = local_4d8;
    *(undefined8 *)(puVar4 + -8) = 0x14000509d;
    RtlVirtualUnwind(0,local_res10,local_3e0,FunctionEntry,*(PCONTEXT *)(puVar4 + 0x20),
                     *(PVOID **)(puVar4 + 0x28),*(PDWORD64 *)(puVar4 + 0x30),
                     *(PKNONVOLATILE_CONTEXT_POINTERS *)(puVar4 + 0x38));
  }
  local_440 = &stack0x00000008;
  *(undefined8 *)(puVar4 + -8) = 0x1400050cf;
  memset(puVar4 + 0x50,0,0x98,puVar4[-8]);
  *(undefined8 *)(puVar4 + 0x60) = in_stack_00000000;
  *(undefined4 *)(puVar4 + 0x50) = 0x40000015;
  *(undefined4 *)(puVar4 + 0x54) = 1;
  *(undefined8 *)(puVar4 + -8) = 0x1400050f1;
  BVar2 = IsDebuggerPresent(puVar4[-8]);
  *(undefined **)(puVar4 + 0x40) = puVar4 + 0x50;
  *(undefined **)(puVar4 + 0x48) = local_4d8;
  *(undefined8 *)(puVar4 + -8) = 0x140005112;
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0,puVar4[-8]);
  *(undefined8 *)(puVar4 + -8) = 0x14000511d;
  LVar3 = UnhandledExceptionFilter((_EXCEPTION_POINTERS *)(puVar4 + 0x40),puVar4[-8]);
  if ((LVar3 == 0) && (BVar2 != 1)) {
    *(undefined8 *)(puVar4 + -8) = 0x14000512d;
    FUN_140004fec(puVar4[-8]);
  }
  return;
}



undefined8 thunk_FUN_140004f7c(void)

{
  return 0;
}



// Library Function - Single Match
//  __scrt_is_managed_app
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

ulonglong __scrt_is_managed_app(void)

{
  HMODULE pHVar1;
  ulonglong uVar2;
  int *piVar3;
  
  pHVar1 = GetModuleHandleW((LPCWSTR)0x0);
  if ((((pHVar1 == (HMODULE)0x0) || (*(short *)&pHVar1->unused != 0x5a4d)) ||
      (piVar3 = (int *)((longlong)&pHVar1->unused + (longlong)pHVar1[0xf].unused), *piVar3 != 0x4550
      )) || (((pHVar1 = (HMODULE)0x20b, *(short *)(piVar3 + 6) != 0x20b ||
              ((uint)piVar3[0x21] < 0xf)) || (piVar3[0x3e] == 0)))) {
    uVar2 = (ulonglong)pHVar1 & 0xffffffffffffff00;
  }
  else {
    uVar2 = 0x201;
  }
  return uVar2;
}



void FUN_14000519c(void)

{
                    // WARNING: Could not recover jumptable at 0x0001400051a3. Too many branches
                    // WARNING: Treating indirect jump as call
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)&LAB_1400051ac);
  return;
}



// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall

void FUN_140005208(void)

{
  code **ppcVar1;
  
  ppcVar1 = (code **)&DAT_1400075d8;
  while (ppcVar1 < &DAT_1400075d8) {
    if (*ppcVar1 != (code *)0x0) {
      (**ppcVar1)();
    }
    ppcVar1 = ppcVar1 + 1;
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x00014000533f)
// WARNING: Removing unreachable block (ram,0x0001400052ba)
// WARNING: Removing unreachable block (ram,0x000140005293)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __isa_available_init
// 
// Library: Visual Studio 2019 Release

undefined8 __isa_available_init(void)

{
  int *piVar1;
  uint *puVar2;
  longlong lVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  byte in_XCR0;
  
  piVar1 = (int *)cpuid_basic_info(0);
  uVar6 = 0;
  puVar2 = (uint *)cpuid_Version_info(1);
  uVar4 = puVar2[3];
  if ((piVar1[1] ^ 0x756e6547U | piVar1[3] ^ 0x6c65746eU | piVar1[2] ^ 0x49656e69U) == 0) {
    _DAT_14000a028 = 0xffffffffffffffff;
    uVar5 = *puVar2 & 0xfff3ff0;
    if ((((uVar5 == 0x106c0) || (uVar5 == 0x20660)) || (uVar5 == 0x20670)) ||
       ((uVar5 - 0x30650 < 0x21 &&
        ((0x100010001U >> ((ulonglong)(uVar5 - 0x30650) & 0x3f) & 1) != 0)))) {
      DAT_14000a8b4 = DAT_14000a8b4 | 1;
    }
  }
  if (6 < *piVar1) {
    lVar3 = cpuid_Extended_Feature_Enumeration_info(7);
    uVar6 = *(uint *)(lVar3 + 4);
    if ((uVar6 >> 9 & 1) != 0) {
      DAT_14000a8b4 = DAT_14000a8b4 | 2;
    }
  }
  _DAT_14000a020 = 1;
  DAT_14000a024 = 2;
  if ((uVar4 >> 0x14 & 1) != 0) {
    _DAT_14000a020 = 2;
    DAT_14000a024 = 6;
    if ((((uVar4 >> 0x1b & 1) != 0) && ((uVar4 >> 0x1c & 1) != 0)) && ((in_XCR0 & 6) == 6)) {
      DAT_14000a024 = 0xe;
      _DAT_14000a020 = 3;
      if ((uVar6 & 0x20) != 0) {
        _DAT_14000a020 = 5;
        DAT_14000a024 = 0x2e;
        if (((uVar6 & 0xd0030000) == 0xd0030000) && ((in_XCR0 & 0xe0) == 0xe0)) {
          DAT_14000a024 = 0x6e;
          _DAT_14000a020 = 6;
        }
      }
    }
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __scrt_is_ucrt_dll_in_use
// 
// Library: Visual Studio 2019 Release

bool __scrt_is_ucrt_dll_in_use(void)

{
  return _DAT_14000a040 != 0;
}



// WARNING: Exceeded maximum restarts with more pending

void _CxxThrowException(void *pExceptionObject,ThrowInfo *pThrowInfo)

{
                    // WARNING: Could not recover jumptable at 0x000140005442. Too many branches
                    // WARNING: Treating indirect jump as call
  _CxxThrowException();
  return;
}



void __current_exception(void)

{
                    // WARNING: Could not recover jumptable at 0x000140005448. Too many branches
                    // WARNING: Treating indirect jump as call
  __current_exception();
  return;
}



void __current_exception_context(void)

{
                    // WARNING: Could not recover jumptable at 0x00014000544e. Too many branches
                    // WARNING: Treating indirect jump as call
  __current_exception_context();
  return;
}



void * memset(void *_Dst,int _Val,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x000140005454. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memset(_Dst,_Val,_Size);
  return pvVar1;
}



int _callnewh(size_t _Size)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00014000545a. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = _callnewh(_Size);
  return iVar1;
}



void * malloc(size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x000140005460. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = malloc(_Size);
  return pvVar1;
}



void _seh_filter_exe(void)

{
                    // WARNING: Could not recover jumptable at 0x000140005466. Too many branches
                    // WARNING: Treating indirect jump as call
  _seh_filter_exe();
  return;
}



void _set_app_type(void)

{
                    // WARNING: Could not recover jumptable at 0x00014000546c. Too many branches
                    // WARNING: Treating indirect jump as call
  _set_app_type();
  return;
}



void __setusermatherr(void)

{
                    // WARNING: Could not recover jumptable at 0x000140005472. Too many branches
                    // WARNING: Treating indirect jump as call
  __setusermatherr();
  return;
}



void _configure_narrow_argv(void)

{
                    // WARNING: Could not recover jumptable at 0x000140005478. Too many branches
                    // WARNING: Treating indirect jump as call
  _configure_narrow_argv();
  return;
}



void _initialize_narrow_environment(void)

{
                    // WARNING: Could not recover jumptable at 0x00014000547e. Too many branches
                    // WARNING: Treating indirect jump as call
  _initialize_narrow_environment();
  return;
}



void _get_initial_narrow_environment(void)

{
                    // WARNING: Could not recover jumptable at 0x000140005484. Too many branches
                    // WARNING: Treating indirect jump as call
  _get_initial_narrow_environment();
  return;
}



void _initterm(void)

{
                    // WARNING: Could not recover jumptable at 0x00014000548a. Too many branches
                    // WARNING: Treating indirect jump as call
  _initterm();
  return;
}



void _initterm_e(void)

{
                    // WARNING: Could not recover jumptable at 0x000140005490. Too many branches
                    // WARNING: Treating indirect jump as call
  _initterm_e();
  return;
}



// WARNING: Exceeded maximum restarts with more pending

void exit(int _Code)

{
                    // WARNING: Could not recover jumptable at 0x000140005496. Too many branches
                    // WARNING: Treating indirect jump as call
  exit();
  return;
}



// WARNING: Exceeded maximum restarts with more pending

void _exit(int _Code)

{
                    // WARNING: Could not recover jumptable at 0x00014000549c. Too many branches
                    // WARNING: Treating indirect jump as call
  _exit();
  return;
}



errno_t _set_fmode(int _Mode)

{
  errno_t eVar1;
  
                    // WARNING: Could not recover jumptable at 0x0001400054a2. Too many branches
                    // WARNING: Treating indirect jump as call
  eVar1 = _set_fmode(_Mode);
  return eVar1;
}



void __p___argc(void)

{
                    // WARNING: Could not recover jumptable at 0x0001400054a8. Too many branches
                    // WARNING: Treating indirect jump as call
  __p___argc();
  return;
}



void __p___argv(void)

{
                    // WARNING: Could not recover jumptable at 0x0001400054ae. Too many branches
                    // WARNING: Treating indirect jump as call
  __p___argv();
  return;
}



void _cexit(void)

{
                    // WARNING: Could not recover jumptable at 0x0001400054b4. Too many branches
                    // WARNING: Treating indirect jump as call
  _cexit();
  return;
}



void _register_thread_local_exe_atexit_callback(void)

{
                    // WARNING: Could not recover jumptable at 0x0001400054c0. Too many branches
                    // WARNING: Treating indirect jump as call
  _register_thread_local_exe_atexit_callback();
  return;
}



int _configthreadlocale(int _Flag)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0001400054c6. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = _configthreadlocale(_Flag);
  return iVar1;
}



void __p__commode(void)

{
                    // WARNING: Could not recover jumptable at 0x0001400054d2. Too many branches
                    // WARNING: Treating indirect jump as call
  __p__commode();
  return;
}



void _initialize_onexit_table(void)

{
                    // WARNING: Could not recover jumptable at 0x0001400054d8. Too many branches
                    // WARNING: Treating indirect jump as call
  _initialize_onexit_table();
  return;
}



void _register_onexit_function(void)

{
                    // WARNING: Could not recover jumptable at 0x0001400054de. Too many branches
                    // WARNING: Treating indirect jump as call
  _register_onexit_function();
  return;
}



void _crt_atexit(void)

{
                    // WARNING: Could not recover jumptable at 0x0001400054e4. Too many branches
                    // WARNING: Treating indirect jump as call
  _crt_atexit();
  return;
}



void free(void *_Memory)

{
                    // WARNING: Could not recover jumptable at 0x0001400054ea. Too many branches
                    // WARNING: Treating indirect jump as call
  free(_Memory);
  return;
}



void terminate(void)

{
                    // WARNING: Could not recover jumptable at 0x0001400054f0. Too many branches
                    // WARNING: Treating indirect jump as call
  terminate();
  return;
}



BOOL IsProcessorFeaturePresent(DWORD ProcessorFeature)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0001400054f6. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = IsProcessorFeaturePresent(ProcessorFeature);
  return BVar1;
}



int memcmp(void *_Buf1,void *_Buf2,size_t _Size)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0001400055f7. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = memcmp(_Buf1,_Buf2,_Size);
  return iVar1;
}



void * memcpy(void *_Dst,void *_Src,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x0001400055fd. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memcpy(_Dst,_Src,_Size);
  return pvVar1;
}



void * memmove(void *_Dst,void *_Src,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x000140005603. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memmove(_Dst,_Src,_Size);
  return pvVar1;
}



// WARNING: This is an inlined function

void _guard_dispatch_icall(void)

{
  code *UNRECOVERED_JUMPTABLE;
  
                    // WARNING: Could not recover jumptable at 0x000140005620. Too many branches
                    // WARNING: Treating indirect jump as call
  (*UNRECOVERED_JUMPTABLE)();
  return;
}



void FUN_140005720(undefined8 param_1,longlong param_2)

{
  if ((*(uint *)(param_2 + 0x20) & 1) != 0) {
    *(uint *)(param_2 + 0x20) = *(uint *)(param_2 + 0x20) & 0xfffffffe;
    std::basic_ios<char,struct_std::char_traits<char>_>::
    _basic_ios_char_struct_std__char_traits_char___
              ((basic_ios_char_struct_std__char_traits_char___ *)
               (*(longlong *)(param_2 + 0x30) + 0xa8));
  }
  return;
}



void FUN_1400057f0(undefined8 param_1,longlong param_2)

{
  if ((*(uint *)(param_2 + 0x20) & 1) != 0) {
    *(uint *)(param_2 + 0x20) = *(uint *)(param_2 + 0x20) & 0xfffffffe;
    FUN_1400033d0(*(void ***)(param_2 + 0x28));
  }
  return;
}



void FUN_14000587f(undefined8 *param_1)

{
  _seh_filter_exe(*(undefined4 *)*param_1,param_1);
  return;
}



// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// Library Function - Single Match
//  public: __cdecl std::_Fac_tidy_reg_t::~_Fac_tidy_reg_t(void) __ptr64
// 
// Library: Visual Studio 2019 Release

void __thiscall std::_Fac_tidy_reg_t::__Fac_tidy_reg_t(_Fac_tidy_reg_t *this)

{
  longlong **pplVar1;
  undefined8 *_Memory;
  code **ppcVar2;
  
  while (_Memory = DAT_14000a2d0, DAT_14000a2d0 != (undefined8 *)0x0) {
    pplVar1 = (longlong **)(DAT_14000a2d0 + 1);
    DAT_14000a2d0 = (undefined8 *)*DAT_14000a2d0;
    ppcVar2 = (code **)(**(code **)(**pplVar1 + 0x10))();
    if (ppcVar2 != (code **)0x0) {
      (**(code **)*ppcVar2)();
    }
    free(_Memory);
  }
  return;
}


