/*
 * Copyright (C) 2015-2018 ZhengHaiTao <ming8ren@163.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef pump_net_iocp_h
#define pump_net_iocp_h

#include "pump/config.h"
#include "pump/net/socket.h"
#include "pump/toolkit/buffer.h"

#if defined(PUMP_HAVE_IOCP)

typedef LONG NTSTATUS;
typedef NTSTATUS *PNTSTATUS;

#ifndef NT_SUCCESS
#define NT_SUCCESS(status) (((NTSTATUS)(status)) >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_PENDING
#define STATUS_PENDING ((NTSTATUS)0x00000103L)
#endif

#ifndef STATUS_CANCELLED
#define STATUS_CANCELLED ((NTSTATUS)0xC0000120L)
#endif

#ifndef STATUS_NOT_FOUND
#define STATUS_NOT_FOUND ((NTSTATUS)0xC0000225L)
#endif

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    } DUMMYUNIONNAME;
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _AFD_POLL_HANDLE_INFO {
    HANDLE Handle;
    ULONG Events;
    LONG Status;
} AFD_POLL_HANDLE_INFO, *PAFD_POLL_HANDLE_INFO;

typedef struct _AFD_POLL_INFO {
    LARGE_INTEGER Timeout;
    ULONG NumberOfHandles;
    ULONG Exclusive;
    AFD_POLL_HANDLE_INFO Handles[1];
} AFD_POLL_INFO, *PAFD_POLL_INFO;

typedef struct _AFD_POLL_EVENT {
    AFD_POLL_INFO info;
    IO_STATUS_BLOCK iosb;
} AFD_POLL_EVENT, *PAFD_POLL_EVENT;

typedef VOID(NTAPI *PIO_APC_ROUTINE)(PVOID ApcContext,
                                     PIO_STATUS_BLOCK IoStatusBlock,
                                     ULONG Reserved);

typedef NTSTATUS(NTAPI *FnNtDeviceIoControlFile)(HANDLE FileHandle,
                                                 HANDLE Event,
                                                 PIO_APC_ROUTINE ApcRoutine,
                                                 PVOID ApcContext,
                                                 PIO_STATUS_BLOCK IoStatusBlock,
                                                 ULONG IoControlCode,
                                                 PVOID InputBuffer,
                                                 ULONG InputBufferLength,
                                                 PVOID OutputBuffer,
                                                 ULONG OutputBufferLength);
extern FnNtDeviceIoControlFile NtDeviceIoControlFile;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef NTSTATUS(NTAPI *FnNtCreateFile)(PHANDLE FileHandle,
                                        ACCESS_MASK DesiredAccess,
                                        POBJECT_ATTRIBUTES ObjectAttributes,
                                        PIO_STATUS_BLOCK IoStatusBlock,
                                        PLARGE_INTEGER AllocationSize,
                                        ULONG FileAttributes,
                                        ULONG ShareAccess,
                                        ULONG CreateDisposition,
                                        ULONG CreateOptions,
                                        PVOID EaBuffer,
                                        ULONG EaLength);
extern FnNtCreateFile NtCreateFile;

typedef NTSTATUS(NTAPI *FnNtCancelIoFileEx)(HANDLE FileHandle,
                                            PIO_STATUS_BLOCK IoRequestToCancel,
                                            PIO_STATUS_BLOCK IoStatusBlock);
extern FnNtCancelIoFileEx NtCancelIoFileEx;

#endif

namespace pump {
namespace net {

pump_socket get_base_socket(pump_socket fd);

}
}  // namespace pump

#endif