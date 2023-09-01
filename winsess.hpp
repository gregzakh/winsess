#pragma once

#ifndef _WINSESS_HPP_
#define _WINSESS_HPP_

#ifndef UNICODE
  #define UNICODE
#endif

#include <windows.h>
#include <algorithm>
#include <functional>
#include <cstdio>
#include <vector>
#include <locale>

template<typename... ArgTypes>
auto err(ArgTypes... args) { fprintf(stderr, args...); }

using KPRIORITY = LONG;

constexpr auto DIRECTORY_QUERY = static_cast<ACCESS_MASK>(0x0001);
constexpr auto STATUS_MORE_ENTRIES = static_cast<NTSTATUS>(0x00000105L);
constexpr auto STATUS_INFO_LENGTH_MISMATCH = static_cast<NTSTATUS>(0xC0000004L);
constexpr auto NT_SUCCESS(NTSTATUS nts) { return nts >= 0L; }

void getlasterror(const DWORD ecode = ::GetLastError()) {
  HLOCAL loc{};
  auto size = ::FormatMessage(
    FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER,
    nullptr, ecode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
    reinterpret_cast<LPWSTR>(&loc), 0, nullptr
  );
  if (!size)
    err("[?] Unknown error has been occured.\n");
  else
    err("[!] %.*ws\n", size - 1, reinterpret_cast<LPWSTR>(loc));

  if (nullptr != ::LocalFree(loc))
    err("[!] LocalFree (%d) fatal error.\n", ::GetLastError());
}

struct UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
};
using PUNICODE_STRING = UNICODE_STRING*;

struct OBJECT_DIRECTORY_INFORMATION {
  UNICODE_STRING Name;
  UNICODE_STRING TypeName;
};

struct OBJECT_ATTRIBUTES {
  ULONG  Length;
  HANDLE RootDirectory;
  PUNICODE_STRING ObjectName;
  ULONG  Attributes;
  PVOID  SecurityDescriptor;
  PVOID  SecurityQualityOfService;
};
using POBJECT_ATTRIBUTES = OBJECT_ATTRIBUTES*;

constexpr void InitializeObjectAttributes(POBJECT_ATTRIBUTES p, PUNICODE_STRING n) {
  p->Length = sizeof(OBJECT_ATTRIBUTES);
  p->RootDirectory = nullptr;
  p->Attributes = 0;
  p->ObjectName = n;
  p->SecurityDescriptor = nullptr;
  p->SecurityQualityOfService = nullptr;
}

struct KSYSTEM_TIME {
  ULONG LowPart;
  LONG  High1Part;
  LONG  High2Part;

  auto asquad(void) {
    return (reinterpret_cast<PLARGE_INTEGER>(this))->QuadPart;
  }
};
using PKSYSTEM_TIME = KSYSTEM_TIME*;

using CSHORT = SHORT;
struct TIME_FIELDS {
  CSHORT Year;
  CSHORT Month;
  CSHORT Day;
  CSHORT Hour;
  CSHORT Minute;
  CSHORT Second;
  CSHORT Milliseconds;
  CSHORT Weekday;

  void gettime(void) {
    printf("%.4hu-%.2hu-%.2hu %.2hu:%.2hu:%.2hu\n",
      this->Year, this->Month, this->Day, this->Hour, this->Minute, this->Second
    );
  }
};
using PTIME_FIELDS = TIME_FIELDS*;

struct OBJECT_BASIC_INFORMATION {
  ULONG Attributes;
  ULONG GrantedAccess;
  ULONG HandleCount;
  ULONG PointerCount;
  ULONG PagedPoolCharge;
  ULONG NonPagedPoolCharge;
  ULONG Reserved[3];
  ULONG NameInfoSize;
  ULONG TypeInfoSize;
  ULONG SecurityDescriptorSize;
  LARGE_INTEGER CreationTime;
};

enum OBJECT_INFORMATION_CLASS {
  ObjectBasicInformation,
  ObjectNameInformation,
  ObjectTypeInformation,
  ObjectTypesInformation,
  ObjectHandleFlagInformation,
  ObjectSessionInformation,
  ObjectSessionObjectInformation,
  MaxObjectInfoClass
};

struct SYSTEM_SESSION_PROCESS_INFORMATION {
  ULONG SessionId;
  ULONG SizeOfBuf;
  PVOID Buffer;
};

struct SYSTEM_PROCESS_INFORMATION {
   ULONG  NextEntryOffset;
   ULONG  NumberOfThreads;
   LARGE_INTEGER WorkingSetPrivateSize;
   ULONG  HardFaultCount;
   ULONG  NumberOfThreadsHighWatermark;
   ULONGLONG CycleTime;
   LARGE_INTEGER CreateTime;
   LARGE_INTEGER UserTime;
   LARGE_INTEGER KernelTime;
   UNICODE_STRING ImageName;
   KPRIORITY BasePriority;
   HANDLE UniqueProcessId;
   HANDLE InheritedFromUniqueProcessId;
   ULONG  HandleCount;
   ULONG  SessionId;
   UINT_PTR UniqueProcessKey;
   SIZE_T PeakVirtualSize;
   SIZE_T VirtualSize;
   ULONG  PageFaultCount;
   SIZE_T PeakWorkingSetSize;
   SIZE_T WorkingSetSize;
   SIZE_T QuotaPeakPagedPoolUsage;
   SIZE_T QuotaPagedPoolUsage;
   SIZE_T QuotaPeakNonPagedPoolUsage;
   SIZE_T QuotaNonPagedPoolUsage;
   SIZE_T PagefileUsage;
   SIZE_T PeakPagefileUsage;
   SIZE_T PrivatePageCount;
   LARGE_INTEGER ReadOperationCount;
   LARGE_INTEGER WriteOperationCount;
   LARGE_INTEGER OtherOperationCount;
   LARGE_INTEGER ReadTransferCount;
   LARGE_INTEGER WriteTransferCount;
   LARGE_INTEGER OtherTransferCount;
};
using PSYSTEM_PROCESS_INFORMATION = SYSTEM_PROCESS_INFORMATION*;

enum SYSTEM_INFORMATION_CLASS { // reduced
  SystemSessionProcessInformation = 53
};

extern "C" {
  NTSYSCALLAPI
  NTSTATUS
  NTAPI
  NtOpenDirectoryObject(
    _Out_ PHANDLE DirectoryHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
  );

  NTSYSCALLAPI
  NTSTATUS
  NTAPI
  NtOpenSymbolicLinkObject(
    _Out_ PHANDLE LinkHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
  );

  NTSYSCALLAPI
  NTSTATUS
  NTAPI
  NtQueryDirectoryObject(
    _In_ HANDLE DirectoryHandle,
    _Out_writes_bytes_opt_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN ReturnSingleEntry,
    _In_ BOOLEAN RestartScan,
    _Inout_ PULONG Context,
    _Out_opt_ PULONG ReturnLength
  );

  NTSYSCALLAPI
  NTSTATUS
  NTAPI
  NtQueryObject(
    _In_opt_ HANDLE Handle,
    _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass,
    _Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation,
    _In_ ULONG ObjectInformationLength,
    _Out_opt_ PULONG ReturnLength
  );

  NTSYSCALLAPI
  NTSTATUS
  NTAPI
  NtQuerySystemInformation(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
  );

  NTSYSAPI
  VOID
  NTAPI
  RtlInitUnicodeString(
    _Out_ PUNICODE_STRING DestinationString,
    _In_opt_z_ PCWSTR SourceString
  );

  NTSYSAPI
  ULONG
  NTAPI
  RtlNtStatusToDosError(
    _In_ NTSTATUS Status
  );

  NTSYSAPI
  VOID
  NTAPI
  RtlTimeToTimeFields(
    _In_ PLARGE_INTEGER Time,
    _Out_ PTIME_FIELDS TimeFields
  );

  NTSYSAPI
  NTSTATUS
  NTAPI
  RtlUnicodeStringToInteger(
    _In_ PUNICODE_STRING String,
    _In_opt_ ULONG Base,
    _Out_ PULONG Value
  );
}

class NtObject {
  private:
    HANDLE hndl;
  private:
    static HANDLE getobject(
      const std::function<NTSTATUS(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)> f,
      const std::wstring& p
    ) {
      HANDLE h = nullptr;
      OBJECT_ATTRIBUTES oa;
      UNICODE_STRING  path;

      ::RtlInitUnicodeString(&path, p.c_str());
      InitializeObjectAttributes(&oa, &path);

      auto nts = f(&h, DIRECTORY_QUERY, &oa);
      if (!NT_SUCCESS(nts))
        getlasterror(::RtlNtStatusToDosError(nts));

      return h;
    }
  public:
    NtObject(
      const std::function<NTSTATUS(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)> f,
      const std::wstring& p
    ) { hndl = getobject(f, p); }

    NtObject(const NtObject&) = delete;
    NtObject& operator=(const NtObject&) = delete;

    ~NtObject() {
      if (nullptr != hndl) {
        if (!::CloseHandle(hndl)) getlasterror();
        //else err("[*] success.\n");
      }
    }

    operator HANDLE() { return hndl; }
    HANDLE* operator&() { return &hndl; }
};

#endif
