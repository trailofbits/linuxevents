/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#ifdef __cplusplus

#pragma once

#include <cstdint>

using u16 = std::uint16_t;
using u64 = std::uint64_t;

#endif

#pragma pack(push, 1)

typedef enum : u16 {
  Execve,
  ProcessInformation,
  BinaryPathArrayEntry,
  ArgumentArrayEntry,
  CgroupPathArrayEntry,
} BufferID;

typedef struct {
  u64 session_id;
  u16 buffer_id;
  u16 size;
} BufferHeader;

#pragma pack(pop)
