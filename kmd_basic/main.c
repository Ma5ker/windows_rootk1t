#include <ntddk.h>

VOID Unload(IN PDRIVER_OBJECT DriverObject) {

	return;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject,IN PUNICODE_STRING regPath) {

	(*DriverObject).DriverUnload = Unload;
	return(STATUS_SUCCESS);
}


