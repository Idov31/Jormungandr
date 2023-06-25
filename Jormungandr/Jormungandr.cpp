#include "pch.h"
#include "Jormungandr.h"

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING deviceName = DRIVER_DEVICE_NAME;
	UNICODE_STRING symbolicLink = DRIVER_SYMBOLIC_LINK;
	PDEVICE_OBJECT DeviceObject = nullptr;

	status = GetSSDTAddress();

	if (!NT_SUCCESS(status))
		return status;

	status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);

	if (!NT_SUCCESS(status)) {
		KdPrint((DRIVER_PREFIX "Failed to create device: (0x%08X)\n", status));
		return status;
	}

	status = IoCreateSymbolicLink(&symbolicLink, &deviceName);

	if (!NT_SUCCESS(status)) {
		KdPrint((DRIVER_PREFIX "Failed to create symbolic link: (0x%08X)\n", status));
		IoDeleteDevice(DeviceObject);
		return status;
	}
	DeviceObject->Flags |= DO_BUFFERED_IO;

	DriverObject->DriverUnload = JormungandrUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = JormungandrCreateClose;
	DriverObject->MajorFunction[IRP_MJ_WRITE] = JormungandrWrite;

	KdPrint((DRIVER_PREFIX "Initialization finished.\n"));
	return status;
}

/*
* Description:
* JormungandrWrite is responsible for handling writing operation to the driver and managing the COFF.
*
* Parameters:
* @DeviceObject [PDEVICE_OBJECT] -- Unused.
* @Irp			[PIRP]			 -- Irp that contains the relevant information about the request.
*
* Returns:
* Always STATUS_SUCCESS.
*/
NTSTATUS JormungandrWrite(PDEVICE_OBJECT, PIRP Irp) {
	NTSTATUS status = STATUS_SUCCESS;
	COFFLdr* coffLoader = NULL;
	SIZE_T len = 0;
	auto stack = IoGetCurrentIrpStackLocation(Irp);

	auto size = stack->Parameters.DeviceIoControl.InputBufferLength;

	if (size % sizeof(COFFData) != 0) {
		status = STATUS_INVALID_BUFFER_SIZE;
		goto Exit;
	}

	coffLoader = new COFFLdr((COFFData*)Irp->AssociatedIrp.SystemBuffer);
	status = coffLoader->IsInitialized();

	if (!NT_SUCCESS(status)) {
		KdPrint((DRIVER_PREFIX "Failed to initialize COFF (0x%08X).\n", status));
		goto Exit;
	}
	status = coffLoader->Load();

	if (!NT_SUCCESS(status)) {
		KdPrint((DRIVER_PREFIX "Failed to load COFF (0x%08X).\n", status));
		goto Exit;
	}
	KdPrint((DRIVER_PREFIX "Loaded COFF, now executing...\n"));
	coffLoader->Execute();
	KdPrint((DRIVER_PREFIX "COFF executed.\n"));

	len += sizeof(COFFData);

Exit:
	if (coffLoader)
		delete coffLoader;

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = len;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

/*
* Description:
* JormungandrCreateClose is responsible for returning STATUS_SUCCESS for an IRP.
*
* Parameters:
* @DeviceObject [PDEVICE_OBJECT] -- Unused.
* @Irp			[PIRP]			 -- Given Irp.
*
* Returns:
* Always STATUS_SUCCESS.
*/
NTSTATUS JormungandrCreateClose(PDEVICE_OBJECT, PIRP Irp) {
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

void JormungandrUnload(PDRIVER_OBJECT DriverObject) {
	KdPrint((DRIVER_PREFIX "Unloading...\n"));

	UNICODE_STRING symbolicLink = DRIVER_SYMBOLIC_LINK;
	IoDeleteSymbolicLink(&symbolicLink);
	IoDeleteDevice(DriverObject->DeviceObject);
}
