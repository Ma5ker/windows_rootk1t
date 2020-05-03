#include <ntddk.h>
#include <windef.h>


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

	//双链表节点脱链
	pre_section->InLoadOrderLinks.Flink = cur_section->InLoadOrderLinks.Flink;
	next_section->InLoadOrderLinks.Blink = cur_section->InLoadOrderLinks.Blink;
	//自循环
	cur_section->InLoadOrderLinks.Flink = (PLIST_ENTRY)cur_section;
	cur_section->InLoadOrderLinks.Blink = (PLIST_ENTRY)cur_section;

	KeLowerIrql(irql);
}




VOID Unload(IN PDRIVER_OBJECT DriverObject) {
	//KdBreakPoint();
	DbgPrintEx(DPFLTR_IHVVIDEO_ID, DPFLTR_WARNING_LEVEL, "Driver unLoaded.\n");

	return;
}


NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING regPath) {
	DbgPrintEx(DPFLTR_IHVVIDEO_ID, DPFLTR_WARNING_LEVEL, "Driver running.\n");
	(*DriverObject).DriverUnload = Unload;
	HideDriver(DriverObject);

	return(STATUS_SUCCESS);
}