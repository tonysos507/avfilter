#include <ntifs.h>
#include <ntintsafe.h>
#include <ntstrsafe.h>
#include <fltKernel.h>
#include <excpt.h>

#define DELAY_ONE_MICROSECOND (-10)
#define DELAY_ONE_MILLISECOND (DELAY_ONE_MICROSECOND * 1000)
#define DELAY_ONE_SECOND (DELAY_ONE_MILLISECOND * 1000)
#define DEVOBJ_LIST_SIZE 64
#define VALID_FAST_IO_DISPATCH_HANDLER(_FastIoDispatchPtr, _FieldName) \
    (((_FastIoDispatchPtr) != NULL) && \
    (((_FastIoDispatchPtr)->SizeOfFastIoDispatch) >= \
    (FIELD_OFFSET(FAST_IO_DISPATCH, _FieldName) + sizeof(void *))) && \
    ((_FastIoDispatchPtr)->_FieldName != NULL))

typedef struct _FSFILTER_DEVICE_EXTENSION
{
	PDEVICE_OBJECT AttachedToDeviceObject;
} FSFILTER_DEVICE_EXTENSION, *PFSFILTER_DEVICE_EXTENSION;

PDRIVER_OBJECT g_fsFilterDriverObject = NULL;


BOOLEAN FsFilterFastIoCheckIfPossible(__in PFILE_OBJECT FileObject, __in PLARGE_INTEGER FileOffset, __in ULONG Length, __in BOOLEAN Wait, __in ULONG LockKey, __in BOOLEAN CheckForReadOperation, __out PIO_STATUS_BLOCK IoStatus, __in PDEVICE_OBJECT DeviceObject)
{
	PDEVICE_OBJECT nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->AttachedToDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;
	if (VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, FastIoCheckIfPossible)) {
		return (fastIoDispatch->FastIoCheckIfPossible)(FileObject, FileOffset, Length, Wait, LockKey, CheckForReadOperation, IoStatus, nextDeviceObject);
	}
	return FALSE;
}

BOOLEAN FsFilterFastIoRead(__in PFILE_OBJECT FileObject, __in PLARGE_INTEGER FileOffset, __in ULONG Length, __in BOOLEAN Wait, __in ULONG LockKey, __out PVOID Buffer, __out PIO_STATUS_BLOCK IoStatus, __in PDEVICE_OBJECT DeviceObject)
{
	PDEVICE_OBJECT    nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->AttachedToDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

	if (VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, FastIoRead))
	{
		return (fastIoDispatch->FastIoRead)(
			FileObject,
			FileOffset,
			Length,
			Wait,
			LockKey,
			Buffer,
			IoStatus,
			nextDeviceObject);
	}

	return FALSE;
}

BOOLEAN FsFilterFastIoWrite(
	__in PFILE_OBJECT       FileObject,
	__in PLARGE_INTEGER     FileOffset,
	__in ULONG              Length,
	__in BOOLEAN            Wait,
	__in ULONG              LockKey,
	__in PVOID              Buffer,
	__out PIO_STATUS_BLOCK  IoStatus,
	__in PDEVICE_OBJECT     DeviceObject
)
{
	PDEVICE_OBJECT    nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->AttachedToDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

	if (VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, FastIoWrite))
	{
		return (fastIoDispatch->FastIoWrite)(
			FileObject,
			FileOffset,
			Length,
			Wait,
			LockKey,
			Buffer,
			IoStatus,
			nextDeviceObject);
	}

	return FALSE;
}

BOOLEAN FsFilterFastIoQueryBasicInfo(
	__in PFILE_OBJECT       FileObject,
	__in BOOLEAN            Wait,
	__out PFILE_BASIC_INFORMATION Buffer,
	__out PIO_STATUS_BLOCK  IoStatus,
	__in PDEVICE_OBJECT     DeviceObject
)
{
	PDEVICE_OBJECT    nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->AttachedToDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

	if (VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, FastIoQueryBasicInfo))
	{

		return (fastIoDispatch->FastIoQueryBasicInfo)(
			FileObject,
			Wait,
			Buffer,
			IoStatus,
			nextDeviceObject);
	}

	return FALSE;
}

BOOLEAN FsFilterFastIoQueryStandardInfo(
	__in PFILE_OBJECT       FileObject,
	__in BOOLEAN            Wait,
	__out PFILE_STANDARD_INFORMATION Buffer,
	__out PIO_STATUS_BLOCK  IoStatus,
	__in PDEVICE_OBJECT     DeviceObject
)
{
	PDEVICE_OBJECT    nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->AttachedToDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

	if (VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, FastIoQueryStandardInfo))
	{
		return (fastIoDispatch->FastIoQueryStandardInfo)(
			FileObject,
			Wait,
			Buffer,
			IoStatus,
			nextDeviceObject);
	}

	return FALSE;
}

BOOLEAN FsFilterFastIoLock(
	__in PFILE_OBJECT       FileObject,
	__in PLARGE_INTEGER     FileOffset,
	__in PLARGE_INTEGER     Length,
	__in PEPROCESS          ProcessId,
	__in ULONG              Key,
	__in BOOLEAN            FailImmediately,
	__in BOOLEAN            ExclusiveLock,
	__out PIO_STATUS_BLOCK  IoStatus,
	__in PDEVICE_OBJECT     DeviceObject
)
{
	PDEVICE_OBJECT    nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->AttachedToDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

	if (VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, FastIoLock))
	{
		return (fastIoDispatch->FastIoLock)(
			FileObject,
			FileOffset,
			Length,
			ProcessId,
			Key,
			FailImmediately,
			ExclusiveLock,
			IoStatus,
			nextDeviceObject);
	}

	return FALSE;
}

BOOLEAN FsFilterFastIoUnlockSingle(
	__in PFILE_OBJECT       FileObject,
	__in PLARGE_INTEGER     FileOffset,
	__in PLARGE_INTEGER     Length,
	__in PEPROCESS          ProcessId,
	__in ULONG              Key,
	__out PIO_STATUS_BLOCK  IoStatus,
	__in PDEVICE_OBJECT     DeviceObject
)
{
	PDEVICE_OBJECT    nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->AttachedToDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

	if (VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, FastIoUnlockSingle))
	{
		return (fastIoDispatch->FastIoUnlockSingle)(
			FileObject,
			FileOffset,
			Length,
			ProcessId,
			Key,
			IoStatus,
			nextDeviceObject);
	}

	return FALSE;
}

BOOLEAN FsFilterFastIoUnlockAll(
	__in PFILE_OBJECT       FileObject,
	__in PEPROCESS          ProcessId,
	__out PIO_STATUS_BLOCK  IoStatus,
	__in PDEVICE_OBJECT     DeviceObject
)
{
	PDEVICE_OBJECT    nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->AttachedToDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

	if (VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, FastIoUnlockAll))
	{
		return (fastIoDispatch->FastIoUnlockAll)(
			FileObject,
			ProcessId,
			IoStatus,
			nextDeviceObject);
	}

	return FALSE;
}

BOOLEAN FsFilterFastIoUnlockAllByKey(
	__in PFILE_OBJECT       FileObject,
	__in PVOID              ProcessId,
	__in ULONG              Key,
	__out PIO_STATUS_BLOCK  IoStatus,
	__in PDEVICE_OBJECT     DeviceObject
)
{
	PDEVICE_OBJECT    nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->AttachedToDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

	if (VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, FastIoUnlockAllByKey))
	{
		return (fastIoDispatch->FastIoUnlockAllByKey)(
			FileObject,
			ProcessId,
			Key,
			IoStatus,
			nextDeviceObject);
	}

	return FALSE;
}

BOOLEAN FsFilterFastIoDeviceControl(
	__in PFILE_OBJECT       FileObject,
	__in BOOLEAN            Wait,
	__in_opt PVOID          InputBuffer,
	__in ULONG              InputBufferLength,
	__out_opt PVOID         OutputBuffer,
	__in ULONG              OutputBufferLength,
	__in ULONG              IoControlCode,
	__out PIO_STATUS_BLOCK  IoStatus,
	__in PDEVICE_OBJECT     DeviceObject
)
{
	PDEVICE_OBJECT    nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->AttachedToDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

	if (VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, FastIoDeviceControl))
	{
		return (fastIoDispatch->FastIoDeviceControl)(
			FileObject,
			Wait,
			InputBuffer,
			InputBufferLength,
			OutputBuffer,
			OutputBufferLength,
			IoControlCode,
			IoStatus,
			nextDeviceObject);
	}

	return FALSE;
}

VOID FsFilterFastIoDetachDevice(
	__in PDEVICE_OBJECT     SourceDevice,
	__in PDEVICE_OBJECT     TargetDevice
)
{
	IoDetachDevice(TargetDevice);
	IoDeleteDevice(SourceDevice);
}

BOOLEAN FsFilterFastIoQueryNetworkOpenInfo(
	__in PFILE_OBJECT       FileObject,
	__in BOOLEAN            Wait,
	__out PFILE_NETWORK_OPEN_INFORMATION Buffer,
	__out PIO_STATUS_BLOCK  IoStatus,
	__in PDEVICE_OBJECT     DeviceObject
)
{
	PDEVICE_OBJECT    nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->AttachedToDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

	if (VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, FastIoQueryNetworkOpenInfo))
	{
		return (fastIoDispatch->FastIoQueryNetworkOpenInfo)(
			FileObject,
			Wait,
			Buffer,
			IoStatus,
			nextDeviceObject);
	}

	return FALSE;
}

BOOLEAN FsFilterFastIoMdlRead(
	__in PFILE_OBJECT       FileObject,
	__in PLARGE_INTEGER     FileOffset,
	__in ULONG              Length,
	__in ULONG              LockKey,
	__out PMDL*             MdlChain,
	__out PIO_STATUS_BLOCK  IoStatus,
	__in PDEVICE_OBJECT     DeviceObject
)
{
	PDEVICE_OBJECT    nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->AttachedToDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

	if (VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, MdlRead))
	{
		return (fastIoDispatch->MdlRead)(
			FileObject,
			FileOffset,
			Length,
			LockKey,
			MdlChain,
			IoStatus,
			nextDeviceObject);
	}

	return FALSE;
}

BOOLEAN FsFilterFastIoMdlReadComplete(
	__in PFILE_OBJECT       FileObject,
	__in PMDL               MdlChain,
	__in PDEVICE_OBJECT     DeviceObject
)
{
	PDEVICE_OBJECT    nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->AttachedToDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

	if (VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, MdlReadComplete))
	{
		return (fastIoDispatch->MdlReadComplete)(
			FileObject,
			MdlChain,
			nextDeviceObject);
	}

	return FALSE;
}

BOOLEAN FsFilterFastIoPrepareMdlWrite(
	__in PFILE_OBJECT       FileObject,
	__in PLARGE_INTEGER     FileOffset,
	__in ULONG              Length,
	__in ULONG              LockKey,
	__out PMDL*             MdlChain,
	__out PIO_STATUS_BLOCK  IoStatus,
	__in PDEVICE_OBJECT     DeviceObject
)
{
	PDEVICE_OBJECT    nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->AttachedToDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

	if (VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, PrepareMdlWrite))
	{
		return (fastIoDispatch->PrepareMdlWrite)(
			FileObject,
			FileOffset,
			Length,
			LockKey,
			MdlChain,
			IoStatus,
			nextDeviceObject);
	}

	return FALSE;
}

BOOLEAN FsFilterFastIoMdlWriteComplete(
	__in PFILE_OBJECT       FileObject,
	__in PLARGE_INTEGER     FileOffset,
	__in PMDL               MdlChain,
	__in PDEVICE_OBJECT     DeviceObject
)
{
	PDEVICE_OBJECT    nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->AttachedToDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

	if (VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, MdlWriteComplete))
	{
		return (fastIoDispatch->MdlWriteComplete)(
			FileObject,
			FileOffset,
			MdlChain,
			nextDeviceObject);
	}

	return FALSE;
}

BOOLEAN FsFilterFastIoReadCompressed(
	__in PFILE_OBJECT       FileObject,
	__in PLARGE_INTEGER     FileOffset,
	__in ULONG              Length,
	__in ULONG              LockKey,
	__out PVOID             Buffer,
	__out PMDL*             MdlChain,
	__out PIO_STATUS_BLOCK  IoStatus,
	__out struct _COMPRESSED_DATA_INFO* CompressedDataInfo,
	__in ULONG              CompressedDataInfoLength,
	__in PDEVICE_OBJECT     DeviceObject
)
{
	PDEVICE_OBJECT    nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->AttachedToDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

	if (VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, FastIoReadCompressed))
	{
		return (fastIoDispatch->FastIoReadCompressed)(
			FileObject,
			FileOffset,
			Length,
			LockKey,
			Buffer,
			MdlChain,
			IoStatus,
			CompressedDataInfo,
			CompressedDataInfoLength,
			nextDeviceObject);
	}

	return FALSE;
}

BOOLEAN FsFilterFastIoWriteCompressed(
	__in PFILE_OBJECT       FileObject,
	__in PLARGE_INTEGER     FileOffset,
	__in ULONG              Length,
	__in ULONG              LockKey,
	__in PVOID              Buffer,
	__out PMDL*             MdlChain,
	__out PIO_STATUS_BLOCK  IoStatus,
	__in struct _COMPRESSED_DATA_INFO*  CompressedDataInfo,
	__in ULONG              CompressedDataInfoLength,
	__in PDEVICE_OBJECT     DeviceObject
)
{
	PDEVICE_OBJECT    nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->AttachedToDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

	if (VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, FastIoWriteCompressed))
	{
		return (fastIoDispatch->FastIoWriteCompressed)(
			FileObject,
			FileOffset,
			Length,
			LockKey,
			Buffer,
			MdlChain,
			IoStatus,
			CompressedDataInfo,
			CompressedDataInfoLength,
			nextDeviceObject);
	}

	return FALSE;
}

BOOLEAN FsFilterFastIoMdlReadCompleteCompressed(
	__in PFILE_OBJECT       FileObject,
	__in PMDL               MdlChain,
	__in PDEVICE_OBJECT     DeviceObject
)
{
	PDEVICE_OBJECT    nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->AttachedToDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

	if (VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, MdlReadCompleteCompressed))
	{
		return (fastIoDispatch->MdlReadCompleteCompressed)(
			FileObject,
			MdlChain,
			nextDeviceObject);
	}

	return FALSE;
}

BOOLEAN FsFilterFastIoMdlWriteCompleteCompressed(
	__in PFILE_OBJECT       FileObject,
	__in PLARGE_INTEGER     FileOffset,
	__in PMDL               MdlChain,
	__in PDEVICE_OBJECT     DeviceObject
)
{
	PDEVICE_OBJECT    nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->AttachedToDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

	if (VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, MdlWriteCompleteCompressed))
	{
		return (fastIoDispatch->MdlWriteCompleteCompressed)(
			FileObject,
			FileOffset,
			MdlChain,
			nextDeviceObject);
	}

	return FALSE;
}

BOOLEAN FsFilterFastIoQueryOpen(
	__in PIRP               Irp,
	__out PFILE_NETWORK_OPEN_INFORMATION NetworkInformation,
	__in PDEVICE_OBJECT     DeviceObject
)
{
	PDEVICE_OBJECT    nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->AttachedToDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

	if (VALID_FAST_IO_DISPATCH_HANDLER(fastIoDispatch, FastIoQueryOpen))
	{
		BOOLEAN result;
		PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);

		//
		//  Before calling the next filter, we must make sure their device
		//  object is in the current stack entry for the given IRP
		//

		irpSp->DeviceObject = nextDeviceObject;

		result = (fastIoDispatch->FastIoQueryOpen)(
			Irp,
			NetworkInformation,
			nextDeviceObject);

		//
		//  Always restore the IRP back to our device object
		//

		irpSp->DeviceObject = DeviceObject;
		return result;
	}

	return FALSE;
}

FAST_IO_DISPATCH g_fastIoDispatch =
{
	sizeof(FAST_IO_DISPATCH),
	FsFilterFastIoCheckIfPossible,
	FsFilterFastIoRead,
	FsFilterFastIoWrite,
	FsFilterFastIoQueryBasicInfo,
	FsFilterFastIoQueryStandardInfo,
	FsFilterFastIoLock,
	FsFilterFastIoUnlockSingle,
	FsFilterFastIoUnlockAll,
	FsFilterFastIoUnlockAllByKey,
	FsFilterFastIoDeviceControl,
	NULL,
	NULL,
	FsFilterFastIoDetachDevice,
	FsFilterFastIoQueryNetworkOpenInfo,
	NULL,
	FsFilterFastIoMdlRead,
	FsFilterFastIoMdlReadComplete,
	FsFilterFastIoPrepareMdlWrite,
	FsFilterFastIoMdlWriteComplete,
	FsFilterFastIoReadCompressed,
	FsFilterFastIoWriteCompressed,
	FsFilterFastIoMdlReadCompleteCompressed,
	FsFilterFastIoMdlWriteCompleteCompressed,
	FsFilterFastIoQueryOpen,
	NULL,
	NULL,
	NULL,
};

void FsFilterDetachFromDevice(__in PDEVICE_OBJECT DeviceObject)
{
	PFSFILTER_DEVICE_EXTENSION pDevExt = (PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
	IoDetachDevice(pDevExt->AttachedToDeviceObject);
	IoDeleteDevice(DeviceObject);
}

BOOLEAN FsFilterIsMyDeviceObject(__in PDEVICE_OBJECT DeviceObject)
{
	return DeviceObject->DriverObject == g_fsFilterDriverObject;
}


BOOLEAN FsFilterIsAttachedToDevice(__in PDEVICE_OBJECT DeviceObject)
{
	PDEVICE_OBJECT nextDevObj = NULL;
	PDEVICE_OBJECT currentDevObj = IoGetAttachedDeviceReference(DeviceObject);

	do
	{
		if (FsFilterIsMyDeviceObject(currentDevObj))
		{
			ObDereferenceObject(currentDevObj);
			return TRUE;
		}
		nextDevObj = IoGetLowerDeviceObject(currentDevObj);
		ObDereferenceObject(currentDevObj);
		currentDevObj = nextDevObj;
	} while (NULL != currentDevObj);

	return FALSE;
}

NTSTATUS FsFilterAttachToDevice(__in PDEVICE_OBJECT DeviceObject, __out_opt PDEVICE_OBJECT* pFilterDeviceObject)
{
	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT filterDeviceObject = NULL;
	PFSFILTER_DEVICE_EXTENSION pDevExt = NULL;
	ULONG i = 0;

	ASSERT(!FsFilterIsAttachedToDevice(DeviceObject));
	
	status = IoCreateDevice(g_fsFilterDriverObject, sizeof(FSFILTER_DEVICE_EXTENSION), NULL, DeviceObject->DeviceType, 0, FALSE, &filterDeviceObject);

	if (!NT_SUCCESS(status))
		return status;

	pDevExt = (PFSFILTER_DEVICE_EXTENSION)filterDeviceObject->DeviceExtension;
	if (FlagOn(DeviceObject->Flags, DO_BUFFERED_IO))
		SetFlag(filterDeviceObject->Flags, DO_BUFFERED_IO);
	if (FlagOn(DeviceObject->Flags, DO_DIRECT_IO))
		SetFlag(filterDeviceObject->Flags, DO_DIRECT_IO);
	if (FlagOn(DeviceObject->Characteristics, FILE_DEVICE_SECURE_OPEN))
		SetFlag(filterDeviceObject->Characteristics, FILE_DEVICE_SECURE_OPEN);

	for (i = 0; i < 8; i++) {
		LARGE_INTEGER interval;
		status = IoAttachDeviceToDeviceStackSafe(filterDeviceObject, DeviceObject, &pDevExt->AttachedToDeviceObject);
		if (NT_SUCCESS(status))
			break;
		interval.QuadPart = (500 * DELAY_ONE_MILLISECOND);
		KeDelayExecutionThread(KernelMode, FALSE, &interval);
	}

	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(filterDeviceObject);
		filterDeviceObject = NULL;
	}
	else {
		ClearFlag(filterDeviceObject->Flags, DO_DEVICE_INITIALIZING);
		if (NULL != pFilterDeviceObject)
			*pFilterDeviceObject = filterDeviceObject;
	}

	return status;
}

NTSTATUS FsFilterEnumerateFileSystemVolumes(__in PDEVICE_OBJECT DeviceObject)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG numDevices = 0;
	ULONG i = 0;
	PDEVICE_OBJECT devList[DEVOBJ_LIST_SIZE];

	status = IoEnumerateDeviceObjectList(DeviceObject->DriverObject, devList, sizeof(devList), &numDevices);
	if (!NT_SUCCESS(status))
		return status;

	numDevices = min(numDevices, RTL_NUMBER_OF(devList));

	for (i = 0; i < numDevices; i++) {
		if (devList[i] != DeviceObject && devList[i]->DeviceType == DeviceObject->DeviceType && !FsFilterIsAttachedToDevice(devList[i]))
			status = FsFilterAttachToDevice(devList[i], NULL);

		ObDereferenceObject(devList[i]);
	}
	return STATUS_SUCCESS;
}

NTSTATUS FsFilterAttachToFileSystemDevice(__in PDEVICE_OBJECT DeviceObject)
{
	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT filterDeviceObject = NULL;

	if (!FsFilterIsAttachedToDevice(DeviceObject))
	{
		status = FsFilterAttachToDevice(DeviceObject, &filterDeviceObject);
		if (!NT_SUCCESS(status))
			return status;

		status = FsFilterEnumerateFileSystemVolumes(DeviceObject);
		if (!NT_SUCCESS(status)) {
			FsFilterDetachFromDevice(filterDeviceObject);
			return status;
		}
	}

	return STATUS_SUCCESS;
}

VOID FsFilterDetachFromFileSystemDevice(__in PDEVICE_OBJECT DeviceObject)
{
	PDEVICE_OBJECT device = NULL;
	for (device = DeviceObject->AttachedDevice; NULL != device; device = device->AttachedDevice) {
		if (FsFilterIsMyDeviceObject(device)) {
			FsFilterDetachFromDevice(device);
			break;
		}
	}
}

VOID FsFilterNotificationCallback(__in PDEVICE_OBJECT DeviceObject, __in BOOLEAN FsActive)
{
	if (FsActive)
		FsFilterAttachToFileSystemDevice(DeviceObject);
	else
		FsFilterDetachFromFileSystemDevice(DeviceObject);
}



NTSTATUS FsFilterDispatchPassThrough(__in PDEVICE_OBJECT DeviceObject, __in PIRP Irp)
{
	PFSFILTER_DEVICE_EXTENSION pDevExt = (PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
	IoSkipCurrentIrpStackLocation(Irp);
	return IoCallDriver(pDevExt->AttachedToDeviceObject, Irp);
}

NTSTATUS FsFilterDispatchCreate(__in PDEVICE_OBJECT DeviceObject, __in PIRP Irp)
{
	PFILE_OBJECT pFileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
	DbgPrint("%wZ\n", &pFileObject->FileName);
	return FsFilterDispatchPassThrough(DeviceObject, Irp);
}


VOID FsFilterUnload(__in PDRIVER_OBJECT DriverObject)
{
	ULONG numDevices = 0;
	ULONG i = 0;
	LARGE_INTEGER interval;
	PDEVICE_OBJECT devList[DEVOBJ_LIST_SIZE];
	DbgPrint("Driver unload\n");
	interval.QuadPart = (5 * DELAY_ONE_SECOND);

	IoUnregisterFsRegistrationChange(DriverObject, FsFilterNotificationCallback);

	for (;;) {
		IoEnumerateDeviceObjectList(DriverObject, devList, sizeof(devList), &numDevices);
		if (0 == numDevices)
			break;
		numDevices = min(numDevices, RTL_NUMBER_OF(devList));
		for (i = 0; i < numDevices; i++) {
			FsFilterDetachFromDevice(devList[i]);
			ObDereferenceObject(devList[i]);
		}

		KeDelayExecutionThread(KernelMode, FALSE, &interval);
	}
}

NTSTATUS DriverEntry(__inout PDRIVER_OBJECT DriverObject, __in PUNICODE_STRING RegistryPath)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG i = 0;

	DbgPrint("Driver load\n");
	g_fsFilterDriverObject = DriverObject;

	for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
		DriverObject->MajorFunction[i] = FsFilterDispatchPassThrough;
	}
	DriverObject->MajorFunction[IRP_MJ_CREATE] = FsFilterDispatchCreate;

	DriverObject->FastIoDispatch = &g_fastIoDispatch;

	status = IoRegisterFsRegistrationChange(DriverObject, FsFilterNotificationCallback);
	if (!NT_SUCCESS(status))
		return status;

	DriverObject->DriverUnload = FsFilterUnload;
	return STATUS_SUCCESS;
}