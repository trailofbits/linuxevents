/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "linuxevents.h"

#include <tob/linuxevents/ilinuxevents.h>

namespace tob::linuxevents {

StringErrorOr<ILinuxEvents::Ptr>
ILinuxEvents::create(std::uint32_t perf_output_size) {
  try {
    return Ptr(new LinuxEvents(perf_output_size));

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}

} // namespace tob::linuxevents
