#include "winsess.hpp"

#pragma comment (lib, "ntdll.lib")

auto tfget(std::function<VOID(PLARGE_INTEGER, PTIME_FIELDS)> f, LONGLONG delta) {
  TIME_FIELDS tf{};
  f(reinterpret_cast<PLARGE_INTEGER>(&delta), &tf);

  return tf;
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
  }

  std::vector<OBJECT_DIRECTORY_INFORMATION> ().swap(buf);

  return 0;
}
