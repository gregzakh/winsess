#include "winsess.hpp"

#pragma comment (lib, "ntdll.lib")

auto tfget(std::function<VOID(PLARGE_INTEGER, PTIME_FIELDS)> f, LONGLONG delta) {
  TIME_FIELDS tf{};
  f(reinterpret_cast<PLARGE_INTEGER>(&delta), &tf);

  return tf;
}

void psenumsess(ULONG id) {
  SYSTEM_SESSION_PROCESS_INFORMATION sspi{};
  std::vector<BYTE> buf(0x1000);
  sspi.SessionId = id;
  sspi.SizeOfBuf = buf.size();
  sspi.Buffer    = &buf[0];

  ULONG req = 0;
  NTSTATUS nts = ::NtQuerySystemInformation(
    SystemSessionProcessInformation, &sspi, sizeof(sspi), &req
  );
  if (STATUS_INFO_LENGTH_MISMATCH != nts) {
    getlasterror(::RtlNtStatusToDosError(nts));
    return;
  }

  buf.resize(req);
  sspi.SizeOfBuf = buf.size();
  sspi.Buffer    = &buf[0];
  nts = ::NtQuerySystemInformation(
    SystemSessionProcessInformation, &sspi, sizeof(sspi), &req
  );
  if (!NT_SUCCESS(nts)) {
    std::vector<BYTE> ().swap(buf);
    getlasterror(::RtlNtStatusToDosError(nts));
    return;
  }

  auto adr = &buf[0];
  auto spi = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(adr);
  while (spi->NextEntryOffset) {
    printf("\t\t%wZ (%llu)\n",
      spi->ImageName, reinterpret_cast<ULONG_PTR>(spi->UniqueProcessId)
    );
    adr += spi->NextEntryOffset;
    spi = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(adr);
  }
  std::vector<BYTE> ().swap(buf);
}

int wmain(void) {
  std::locale::global(std::locale(""));
  auto bsz{0x100ul}, items{0ul}, bytes{0ul};
  std::vector<OBJECT_DIRECTORY_INFORMATION> buf(bsz);
  std::wstring bnolinks = L"\\Sessions\\BNOLINKS";
  std::vector<LONGLONG> vals{0x7FFE0008, 0x7FFE0014, 0x7FFE0020};

  NtObject sess(::NtOpenDirectoryObject, bnolinks);
  if (!sess) return 1;
  while (STATUS_MORE_ENTRIES == ::NtQueryDirectoryObject(
    sess, &buf[0], bsz, FALSE, TRUE, &items, &bytes
  )) {
    bsz += bytes;
    buf.resize(bsz);
  }

  std::transform(vals.begin(), vals.end(), vals.begin(), [](LONGLONG const addr) {
    return (*reinterpret_cast<PKSYSTEM_TIME>(addr)).asquad();
  });
  printf("System boot time: ");
  tfget(::RtlTimeToTimeFields, vals[1] - vals[2] - vals[0]).gettime();

  ULONG id{};
  for (auto i = 0; i < items; i++) {
    printf("\tSession %wZ starts at ", &buf[i].Name);
    NtObject tmp(::NtOpenSymbolicLinkObject, bnolinks + L"\\" + buf[i].Name.Buffer);
    OBJECT_BASIC_INFORMATION obi{};
    auto nts = ::NtQueryObject(tmp, ObjectBasicInformation, &obi, sizeof(obi), nullptr);
    if (!NT_SUCCESS(nts)) {
      getlasterror(::RtlNtStatusToDosError(nts));
      continue;
    }
    tfget(::RtlTimeToTimeFields, obi.CreationTime.QuadPart - vals[2]).gettime();
    nts = ::RtlUnicodeStringToInteger(&buf[i].Name, 0, &id);
    if (!NT_SUCCESS(nts)) {
      getlasterror(::RtlNtStatusToDosError(nts));
      continue;
    }
    psenumsess(id);
  }

  std::vector<OBJECT_DIRECTORY_INFORMATION> ().swap(buf);

  return 0;
}
