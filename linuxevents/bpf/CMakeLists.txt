#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.14.6)

set(source_file_list
  src/sched_process_exec.c
)

set(header_file_list
  include/tob/linuxevents/buffer.h
)

set(include_dir_path
  "${CMAKE_CURRENT_BINARY_DIR}/include/tob/linuxevents/bpf"
)

add_custom_command(
  OUTPUT "${include_dir_path}"
  COMMAND "${CMAKE_COMMAND}" -E make_directory "${include_dir_path}"
  VERBATIM
  COMMENT "linuxevents - Generating BPF probe include directory: ${include_dir_path}" 
)

add_custom_target("linuxevents_bpf_probes_include_dir"
  DEPENDS "${include_dir_path}"
)

add_library("linuxevents_bpf_probes" INTERFACE)
target_include_directories("linuxevents_bpf_probes" INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
  "${CMAKE_CURRENT_BINARY_DIR}/include"
)

foreach(relative_file_path ${source_file_list} ${header_file_list})
  list(APPEND file_dependency_list "${PROJECT_SOURCE_DIR}/linuxevents/bpf/${relative_file_path}")
endforeach()

foreach(source_file_path ${source_file_list})
  get_filename_component(probe_name "${source_file_path}" NAME_WE)
  set(source_file_path "${PROJECT_SOURCE_DIR}/linuxevents/bpf/${source_file_path}")

  set(output_file_name "${probe_name}.h")
  set(output_file_path "${include_dir_path}/${output_file_name}")

  unset(header_file_list_commands)

  foreach(header_file_path ${header_file_list})
    list(APPEND header_file_list_commands
      COMMAND "${CMAKE_COMMAND}" -E cat "${header_file_path}" >> "${output_file_path}"
    )
  endforeach()

  add_custom_command(
    OUTPUT "${output_file_path}"
    DEPENDS ${file_dependency_list}
    COMMAND "${CMAKE_COMMAND}" -E echo "// Auto-generated, do not edit!" > "${output_file_path}"
    COMMAND "${CMAKE_COMMAND}" -E echo "namespace tob::linuxevents::${probe_name} {" >> "${output_file_path}"
    COMMAND "${CMAKE_COMMAND}" -E echo "const std::string kProbeSource{R\"src(" >> "${output_file_path}"
    ${header_file_list_commands}
    COMMAND "${CMAKE_COMMAND}" -E cat "${source_file_path}" >> "${output_file_path}"
    COMMAND "${CMAKE_COMMAND}" -E echo ")src\"};" >> "${output_file_path}"
    COMMAND "${CMAKE_COMMAND}" -E echo "}" >> "${output_file_path}"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    VERBATIM
    COMMENT "linuxevents - Generating BPF probe: ${output_file_path}"
  )

  set(target_name
    "linuxevents_${probe_name}"
  )

  add_custom_target("${target_name}"
    DEPENDS "${output_file_path}"
  )

  add_dependencies("${target_name}"
    "linuxevents_bpf_probes_include_dir"
  )

  add_dependencies("linuxevents_bpf_probes"
    "${target_name}"
  )
endforeach()
