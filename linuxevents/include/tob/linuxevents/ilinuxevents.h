/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma once

#include <memory>
#include <string>
#include <vector>

#include <tob/error/stringerror.h>

namespace tob::linuxevents {

class ILinuxEvents {
public:
  using Ptr = std::unique_ptr<ILinuxEvents>;
  static StringErrorOr<Ptr> create(std::uint32_t perf_output_size);

  struct Event final {
    std::uint64_t ktime;
    std::uint32_t parent_process_id;
    std::uint32_t process_id;
    std::string binary_path;
    std::string cgroup_path;
    std::vector<std::string> argument_list;
  };

  using EventList = std::vector<Event>;

  struct ErrorCounters final {
    std::size_t lost_event_count{};
    std::size_t read_error_count{};
    std::size_t invalid_data_count{};
  };

  virtual StringErrorOr<EventList>
  processEvents(ErrorCounters &error_counters) = 0;

  ILinuxEvents() = default;
  virtual ~ILinuxEvents() = default;

  ILinuxEvents(const ILinuxEvents &) = delete;
  ILinuxEvents &operator=(const ILinuxEvents &) = delete;
};

} // namespace tob::linuxevents
