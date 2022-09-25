/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "linuxevents.h"

#include <tob/linuxevents/bpf/sched_process_exec.h>
#include <tob/linuxevents/buffer.h>

#include <tob/ebpf/bpfmap.h>
#include <tob/ebpf/ebpf_utils.h>
#include <tob/ebpf/iclangcompiler.h>
#include <tob/ebpf/iperfevent.h>
#include <tob/ebpf/perfeventarray.h>
#include <tob/utils/bufferreader.h>

namespace tob::linuxevents {

namespace {

const std::size_t kScratchSpaceSize{4096};
const std::size_t kMaxPossibleCpuCount{8192};

struct EventContext final {
  std::uint64_t ktime;
  std::uint32_t parent_process_id;
  std::uint32_t process_id;
  std::vector<std::string> binary_path_entry_list;
  std::vector<std::string> argument_array;
  std::vector<std::string> cgroup_path_entry_list;
};

using ScratchSpaceMap = ebpf::BPFMap<BPF_MAP_TYPE_PERCPU_ARRAY, std::uint32_t>;
using SessionCounterMap = ebpf::BPFMap<BPF_MAP_TYPE_ARRAY, std::uint32_t>;

const std::string kVmlinuxBtfFilePath{"/sys/kernel/btf/vmlinux"};

} // namespace

struct LinuxEvents::PrivateData final {
  ebpf::PerfEventArray::Ref perf_event_array;
  ebpf::IPerfEvent::Ref perf_event;
  ScratchSpaceMap::Ref scratch_space_map;
  SessionCounterMap::Ref session_counter_map;
  std::unordered_map<std::uint64_t, EventContext> event_context_map;
  utils::BufferReader::Ptr buffer_reader;
  std::vector<char> read_buffer;
};

LinuxEvents::~LinuxEvents() {}

StringErrorOr<LinuxEvents::EventList>
LinuxEvents::processEvents(ErrorCounters &error_counters) {
  EventList event_list;

  std::size_t lost_event_count{};
  std::size_t read_error_count{};

  ebpf::PerfEventArray::BufferList buffer_list;
  if (!d->perf_event_array->read(buffer_list, read_error_count,
                                 lost_event_count)) {
    return StringError::create("Failed to read from the perf event array");
  }

  error_counters.lost_event_count += lost_event_count;
  error_counters.read_error_count += read_error_count;

  for (const auto &buffer : buffer_list) {
    d->buffer_reader->reset(buffer);
    d->buffer_reader->skipBytes(ebpf::kPerfEventHeaderSize +
                                sizeof(std::uint32_t));

    BufferHeader buffer_header;
    buffer_header.session_id = d->buffer_reader->u64();
    buffer_header.buffer_id = d->buffer_reader->u16();
    buffer_header.size = d->buffer_reader->u16();

    auto event_context_it = d->event_context_map.find(buffer_header.session_id);
    if (event_context_it == d->event_context_map.end()) {
      // Do not create a new event context if this event is already
      // in the closing stage
      if (buffer_header.buffer_id == Execve) {
        continue;
      }

      // TODO(alessandro): Mark this new session somewhere, then expire it
      // if the event is not closed soon enough
      auto insert_status =
          d->event_context_map.insert({buffer_header.session_id, {}});

      event_context_it = insert_status.first;
    }

    auto &event_context = event_context_it->second;
    bool destroy_event{false};

    switch (buffer_header.buffer_id) {
    case Execve: {
      std::string binary_path;
      for (auto it = event_context.binary_path_entry_list.rbegin();
           it != event_context.binary_path_entry_list.rend(); ++it) {
        const auto &binary_path_entry = *it;

        binary_path += "/" + binary_path_entry;
      }

      std::string cgroup_path;
      for (auto it = event_context.cgroup_path_entry_list.rbegin();
           it != event_context.cgroup_path_entry_list.rend(); ++it) {
        const auto &cgroup_path_entry = *it;

        cgroup_path += "/" + cgroup_path_entry;
      }

      Event event;
      event.binary_path = std::move(binary_path);
      event.ktime = event_context.ktime;
      event.parent_process_id = event_context.parent_process_id;
      event.process_id = event_context.process_id;
      event.cgroup_path = std::move(cgroup_path);
      event.argument_list = std::move(event_context.argument_array);
      event_list.push_back(std::move(event));

      destroy_event = true;
      break;
    }

    case ProcessInformation: {
      event_context.ktime = d->buffer_reader->u64();
      event_context.parent_process_id = d->buffer_reader->u32();
      event_context.process_id = d->buffer_reader->u32();

      break;
    }

    case BinaryPathArrayEntry:
    case ArgumentArrayEntry:
    case CgroupPathArrayEntry: {
      if (buffer_header.size == 0) {
        break;
      }

      auto buffer_size = static_cast<std::size_t>(buffer_header.size);
      buffer_size = std::min(buffer_size, d->read_buffer.size());

      d->buffer_reader->read(d->read_buffer.data(), buffer_size);

      auto buffer_start_ptr = d->read_buffer.data();

      auto buffer_end_ptr = static_cast<const char *>(
          std::memchr(buffer_start_ptr, 0, buffer_size));

      buffer_end_ptr = (buffer_end_ptr != nullptr)
                           ? buffer_end_ptr
                           : buffer_start_ptr + buffer_size;

      buffer_size = static_cast<std::size_t>(buffer_end_ptr - buffer_start_ptr);
      std::string string_entry(buffer_start_ptr, buffer_size);

      if (buffer_header.buffer_id == BinaryPathArrayEntry) {
        event_context.binary_path_entry_list.push_back(std::move(string_entry));

      } else if (buffer_header.buffer_id == ArgumentArrayEntry) {
        event_context.argument_array.push_back(std::move(string_entry));

      } else {
        event_context.cgroup_path_entry_list.push_back(std::move(string_entry));
      }

      break;
    }

    default:
      error_counters.invalid_data_count++;
      destroy_event = true;
    }

    if (destroy_event) {
      d->event_context_map.erase(event_context_it);
    }
  }

  return event_list;
}

LinuxEvents::LinuxEvents() : d(new PrivateData) {
  d->read_buffer.resize(kScratchSpaceSize);

  auto compiler_exp = ebpf::IClangCompiler::create(kVmlinuxBtfFilePath);
  if (!compiler_exp.succeeded()) {
    throw StringError::create(compiler_exp.error().message());
  }

  auto compiler = compiler_exp.takeValue();

  auto perf_event_array_exp = ebpf::PerfEventArray::create(12);
  if (!perf_event_array_exp.succeeded()) {
    throw perf_event_array_exp.error();
  }

  d->perf_event_array = perf_event_array_exp.takeValue();

  auto scratch_space_map_exp = ScratchSpaceMap::create(kScratchSpaceSize, 1U);
  if (!scratch_space_map_exp.succeeded()) {
    throw scratch_space_map_exp.error();
  }

  d->scratch_space_map = scratch_space_map_exp.takeValue();

  auto session_counter_map_exp =
      SessionCounterMap::create(sizeof(std::uint32_t), kMaxPossibleCpuCount);

  if (!session_counter_map_exp.succeeded()) {
    throw session_counter_map_exp.error();
  }

  d->session_counter_map = session_counter_map_exp.takeValue();

  ebpf::IClangCompiler::DefinitionList definition_list;
  definition_list.push_back(
      {"PERF_EVENT_OUTPUT", std::to_string(d->perf_event_array->fd())});

  definition_list.push_back(
      {"SCRATCH_SPACE_MAP", std::to_string(d->scratch_space_map->fd())});

  definition_list.push_back(
      {"SCRATCH_SPACE_SIZE", std::to_string(kScratchSpaceSize)});

  definition_list.push_back(
      {"SESSION_COUNTER_MAP", std::to_string(d->session_counter_map->fd())});

  definition_list.push_back(
      {"SESSION_COUNTER_MAP_ENTRY_SIZE", std::to_string(kMaxPossibleCpuCount)});

  auto program_map_exp =
      compiler->build(sched_process_exec::kProbeSource, definition_list);

  if (!program_map_exp.succeeded()) {
    throw program_map_exp.error();
  }

  auto program_map = program_map_exp.takeValue();
  if (program_map.size() != 1) {
    throw StringError::create("Failed to acquire the compiled BPF program");
  }

  const auto &program = program_map.at("section_sched_process_exec");

  auto perf_event_exp =
      ebpf::IPerfEvent::createTracepoint("sched", "sched_process_exec");

  if (!perf_event_exp.succeeded()) {
    throw perf_event_exp.error();
  }

  d->perf_event = perf_event_exp.takeValue();

  auto program_exp = ebpf::loadProgram(program, *d->perf_event.get());
  if (!program_exp.succeeded()) {
    throw program_exp.error();
  }

  auto buffer_reader_exp = utils::BufferReader::create();
  if (!buffer_reader_exp.succeeded()) {
    throw buffer_reader_exp.error();
  }

  d->buffer_reader = buffer_reader_exp.takeValue();
}

} // namespace tob::linuxevents
