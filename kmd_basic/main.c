#include <ntddk.h>

VOID Unload(IN PDRIVER_OBJECT DriverObject) {
	DbgPrintEx(DPFLTR_IHVVIDEO_ID, DPFLTR_WARNING_LEVEL, "Unload the driver.\n");
	return;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject,IN PUNICODE_STRING regPath) {

	DbgPrintEx(DPFLTR_IHVVIDEO_ID, DPFLTR_WARNING_LEVEL, "Hello world.\n");
	(*DriverObject).DriverUnload = Unload;
	return(STATUS_SUCCESS);
}
