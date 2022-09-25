/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#pragma pack(push, 1)

typedef struct {
  BufferHeader header;
  u8 data[SCRATCH_SPACE_SIZE - sizeof(BufferHeader)];
} DataBuffer;

typedef struct {
  BufferHeader header;
  u64 ktime;
  u32 parent_process_id;
  u32 process_id;
} ProcessInformationBuffer;

#pragma pack(pop)

static u64 generateSessionID() {
  u32 cpu_id = bpf_get_smp_processor_id();
  if (cpu_id >= SESSION_COUNTER_MAP_ENTRY_SIZE) {
    return 0;
  }

  u32 *session_counter_ptr =
      bpf_map_lookup_elem(BPF_PSEUDO_MAP_FD(SESSION_COUNTER_MAP), &cpu_id);

  if (session_counter_ptr == 0) {
    return 0;
  }

  u64 counter_part = (u64)((*session_counter_ptr)++);
  u64 cpu_id_part = ((u64)cpu_id) << 32;

  return cpu_id_part | counter_part;
}

static void capturePath(struct pt_regs *ctx, u64 session_id,
                        struct path *f_path) {
  u32 zero = 0;
  DataBuffer *buffer =
      bpf_map_lookup_elem(BPF_PSEUDO_MAP_FD(SCRATCH_SPACE_MAP), &zero);

  if (buffer == 0) {
    return;
  }

  buffer->header.session_id = session_id;
  buffer->header.buffer_id = (u16)BinaryPathArrayEntry;

  struct vfsmount *current_vfsmount_ptr = f_path->mnt;
  struct dentry *current_dentry_ptr = f_path->dentry;

  struct vfsmount current_vfsmount;
  if (bpf_probe_read_kernel(&current_vfsmount, sizeof(struct vfsmount),
                            current_vfsmount_ptr) != 0) {
    return;
  }

  for (u32 i = 0; i < 32; i++) {
    struct dentry current_dentry = {};
    if (bpf_probe_read_kernel(&current_dentry, sizeof(struct dentry),
                              current_dentry_ptr) != 0) {
      return;
    }

    if (current_dentry_ptr == current_vfsmount.mnt_root) {
      struct mount *current_mount_ptr =
          (struct mount *)(((u8 *)current_vfsmount_ptr) -
                           offsetof(struct mount, mnt));

      struct dentry *mount_point_dentry_ptr = 0;
      if (bpf_probe_read_kernel_struct_member(struct mount, mnt_mountpoint,
                                              current_mount_ptr,
                                              &mount_point_dentry_ptr) != 0) {
        return;
      }

      if (current_dentry_ptr == mount_point_dentry_ptr) {
        break;
      }

      current_dentry_ptr = mount_point_dentry_ptr;

      struct mount *parent_mount_ptr = 0;
      if (bpf_probe_read_kernel_struct_member(struct mount, mnt_parent,
                                              current_mount_ptr,
                                              &parent_mount_ptr) != 0) {
        return;
      }

      struct vfsmount *parent_vfsmount_ptr =
          (struct vfsmount *)(((u8 *)parent_mount_ptr) +
                              offsetof(struct mount, mnt));

      if (current_vfsmount_ptr == parent_vfsmount_ptr) {
        break;
      }

      current_vfsmount_ptr = parent_vfsmount_ptr;
      if (bpf_probe_read_kernel(&current_vfsmount, sizeof(struct vfsmount),
                                current_vfsmount_ptr) != 0) {
        break;
      }

    } else {
      current_dentry_ptr = current_dentry.d_parent;

      long string_size = bpf_probe_read_kernel_str(
          buffer->data, sizeof(buffer->data), current_dentry.d_name.name);

      buffer->header.size = (u16)string_size;

      u64 buffer_size = sizeof(BufferHeader) + buffer->header.size;
      buffer_size =
          (buffer_size > SCRATCH_SPACE_SIZE) ? SCRATCH_SPACE_SIZE : buffer_size;

      bpf_perf_event_output(ctx, BPF_PSEUDO_MAP_FD(PERF_EVENT_OUTPUT), (u32)-1,
                            buffer, buffer_size);
    }
  }
}

static void captureExecutablePath(struct pt_regs *ctx, u64 session_id) {
  struct task_struct *current_task =
      (struct task_struct *)bpf_get_current_task();

  if (current_task == 0) {
    return;
  }

  struct mm_struct *mm = 0;
  if (bpf_probe_read_kernel_struct_member(struct task_struct, mm, current_task,
                                          &mm) != 0) {
    return;
  }

  struct file *exe_file;
  if (bpf_probe_read_kernel_struct_member(struct mm_struct, exe_file, mm,
                                          &exe_file) != 0) {
    return;
  }

  struct path f_path = {0};
  if (bpf_probe_read_kernel_struct_member(struct file, f_path, exe_file,
                                          &f_path) != 0) {
    return;
  }

  capturePath(ctx, session_id, &f_path);
}

static void captureProcessInformation(struct pt_regs *ctx, u64 session_id) {
  ProcessInformationBuffer buffer;
  buffer.header.session_id = session_id;
  buffer.header.buffer_id = (u16)ProcessInformation;
  buffer.header.size = sizeof(ProcessInformationBuffer) - sizeof(BufferHeader);

  buffer.ktime = bpf_ktime_get_ns();
  buffer.process_id = (u32)(bpf_get_current_pid_tgid() & 0xFFFFFFFF);

  struct task_struct *current_task =
      (struct task_struct *)bpf_get_current_task();

  struct task_struct *real_parent = 0;
  if (bpf_probe_read_kernel_struct_member(struct task_struct, real_parent,
                                          current_task, &real_parent) != 0) {
    return;
  }

  if (bpf_probe_read_kernel_struct_member(struct task_struct, tgid, real_parent,
                                          &buffer.parent_process_id) != 0) {
    return;
  }

  bpf_perf_event_output(ctx, BPF_PSEUDO_MAP_FD(PERF_EVENT_OUTPUT), (u32)-1,
                        &buffer, sizeof(ProcessInformationBuffer));
}

static void captureArgumentList(struct pt_regs *ctx, u64 session_id) {
  struct task_struct *current_task =
      (struct task_struct *)bpf_get_current_task();

  if (current_task == 0) {
    return;
  }

  struct mm_struct *mm = 0;
  if (bpf_probe_read_kernel_struct_member(struct task_struct, mm, current_task,
                                          &mm) != 0) {
    return;
  }

  const char *arg_start = 0;
  if (bpf_probe_read_kernel_struct_member(struct mm_struct, arg_start, mm,
                                          &arg_start) != 0) {
    return;
  }

  const char *arg_end = 0;
  if (bpf_probe_read_kernel_struct_member(struct mm_struct, arg_end, mm,
                                          &arg_end) != 0) {
    return;
  }

  u32 zero = 0;
  DataBuffer *buffer =
      bpf_map_lookup_elem(BPF_PSEUDO_MAP_FD(SCRATCH_SPACE_MAP), &zero);

  if (buffer == 0) {
    return;
  }

  buffer->header.session_id = session_id;
  buffer->header.buffer_id = (u16)ArgumentArrayEntry;

  const char *current_argument = arg_start;

  for (u32 i = 0; i < 32; ++i) {
    if (current_argument >= arg_end) {
      break;
    }

    long string_size = bpf_probe_read_user_str(
        &buffer->data, sizeof(buffer->data), current_argument);

    if (string_size == 0) {
      break;
    }

    buffer->header.size = (u16)string_size;

    u64 buffer_size = sizeof(BufferHeader) + buffer->header.size;
    buffer_size =
        (buffer_size > SCRATCH_SPACE_SIZE) ? SCRATCH_SPACE_SIZE : buffer_size;

    bpf_perf_event_output(ctx, BPF_PSEUDO_MAP_FD(PERF_EVENT_OUTPUT), (u32)-1,
                          buffer, buffer_size);

    current_argument += buffer->header.size;
  }
}

static void captureCgroupPath(struct pt_regs *ctx, u64 session_id) {
  struct task_struct *current_task =
      (struct task_struct *)bpf_get_current_task();

  if (current_task == 0) {
    return;
  }

  struct css_set *cgroups = 0;
  if (bpf_probe_read_kernel_struct_member(struct task_struct, cgroups,
                                          current_task, &cgroups) != 0) {
    return;
  }

  struct cgroup_subsys_state *subsys = 0;
  if (bpf_probe_read_kernel_struct_member(struct css_set, subsys, cgroups,
                                          &subsys) != 0) {
    return;
  }

  struct cgroup *cgroup = 0;
  if (bpf_probe_read_kernel_struct_member(struct cgroup_subsys_state, cgroup,
                                          subsys, &cgroup) != 0) {
    return;
  }

  struct kernfs_node *kn = 0;
  if (bpf_probe_read_kernel_struct_member(struct cgroup, kn, cgroup, &kn) !=
      0) {
    return;
  }

  struct kernfs_node *parent_kn = 0;
  if (bpf_probe_read_kernel_struct_member(struct kernfs_node, parent, kn,
                                          &parent_kn) != 0) {
    return;
  }

  u32 zero = 0;
  DataBuffer *buffer =
      bpf_map_lookup_elem(BPF_PSEUDO_MAP_FD(SCRATCH_SPACE_MAP), &zero);

  if (buffer == 0) {
    return;
  }

  buffer->header.session_id = session_id;
  buffer->header.buffer_id = (u16)CgroupPathArrayEntry;

  const char *parent_name = 0;
  if (bpf_probe_read_kernel_struct_member(struct kernfs_node, name, parent_kn,
                                          &parent_name) == 0) {
    long string_size = bpf_probe_read_kernel_str(
        buffer->data, sizeof(buffer->data), parent_name);

    buffer->header.size = (u16)string_size;

    u64 buffer_size = sizeof(BufferHeader) + buffer->header.size;
    buffer_size =
        (buffer_size > SCRATCH_SPACE_SIZE) ? SCRATCH_SPACE_SIZE : buffer_size;

    bpf_perf_event_output(ctx, BPF_PSEUDO_MAP_FD(PERF_EVENT_OUTPUT), (u32)-1,
                          buffer, buffer_size);
  }

  const char *name = 0;
  if (bpf_probe_read_kernel_struct_member(struct kernfs_node, name, kn,
                                          &name) == 0) {
    long string_size =
        bpf_probe_read_kernel_str(buffer->data, sizeof(buffer->data), name);

    buffer->header.size = (u16)string_size;

    u64 buffer_size = sizeof(BufferHeader) + buffer->header.size;
    buffer_size =
        (buffer_size > SCRATCH_SPACE_SIZE) ? SCRATCH_SPACE_SIZE : buffer_size;

    bpf_perf_event_output(ctx, BPF_PSEUDO_MAP_FD(PERF_EVENT_OUTPUT), (u32)-1,
                          buffer, buffer_size);
  }
}

int sched_process_exec(struct pt_regs *ctx) {
  u64 session_id = generateSessionID();
  if (session_id == 0) {
    return 0;
  }

  captureProcessInformation(ctx, session_id);
  captureExecutablePath(ctx, session_id);
  captureArgumentList(ctx, session_id);
  captureCgroupPath(ctx, session_id);

  BufferHeader buffer_header;
  buffer_header.session_id = session_id;
  buffer_header.buffer_id = (u16)Execve;
  buffer_header.size = 0;

  bpf_perf_event_output(ctx, BPF_PSEUDO_MAP_FD(PERF_EVENT_OUTPUT), (u32)-1,
                        &buffer_header, sizeof(BufferHeader));

  return 0;
}
