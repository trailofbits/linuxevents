/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <tob/linuxevents/ilinuxevents.h>

namespace tob::linuxevents {

class LinuxEvents final : public ILinuxEvents {
public:
  virtual ~LinuxEvents() override;

  virtual StringErrorOr<EventList>
  processEvents(ErrorCounters &error_counters) override;

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  LinuxEvents(std::uint32_t perf_output_size);

  friend class ILinuxEvents;
};

} // namespace tob::linuxevents
