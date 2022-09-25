/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include <iostream>

#include <tob/linuxevents/ilinuxevents.h>

void printEvent(const tob::linuxevents::ILinuxEvents::Event &event) {
  std::cout << "event:execve"
            << " ktime:" << event.ktime << " ppid:" << event.parent_process_id
            << " pid:" << event.process_id
            << " binary_path:" << event.binary_path
            << " cgroup_path:" << event.cgroup_path;

  std::cout << " argv:[";

  for (auto argument_it = event.argument_list.begin();
       argument_it != event.argument_list.end(); ++argument_it) {

    const auto &argument = *argument_it;

    auto quote_string = (argument.find(' ') != std::string::npos);
    if (quote_string) {
      std::cout << "\"";
    }

    for (const auto &c : argument) {
      if (c == '"') {
        std::cout << "\\\"";
      } else {
        std::cout << c;
      }
    }

    if (quote_string) {
      std::cout << "\"";
    }

    if (std::next(argument_it, 1) != event.argument_list.end()) {
      std::cout << ", ";
    }
  }

  std::cout << "]\n";
}

int main() {
  auto linux_events_exp = tob::linuxevents::ILinuxEvents::create();
  if (!linux_events_exp.succeeded()) {
    std::cerr << "Failed to create the LinuxEvents object: "
              << linux_events_exp.error().message() << "\n";
    return 1;
  }

  auto linux_events = linux_events_exp.takeValue();

  for (;;) {
    tob::linuxevents::ILinuxEvents::ErrorCounters error_counters;

    auto event_list_exp = linux_events->processEvents(error_counters);
    if (!event_list_exp.succeeded()) {
      std::cerr << event_list_exp.error().message() << "\n";
      break;
    }

    if (error_counters.lost_event_count != 0) {
      std::cerr << "Lost events: " << error_counters.lost_event_count << "\n";
    }

    if (error_counters.read_error_count != 0) {
      std::cerr << "Read error count: " << error_counters.read_error_count
                << "\n";
    }

    if (error_counters.invalid_data_count != 0) {
      std::cerr << "Invalid data: " << error_counters.invalid_data_count
                << "\n";
    }

    error_counters = {};

    auto event_list = event_list_exp.takeValue();

    for (const auto &event : event_list) {
      printEvent(event);
    }
  }

  return 0;
}
