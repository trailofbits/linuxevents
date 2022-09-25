#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.14.6)

add_library("linuxevents"
  include/tob/linuxevents/ilinuxevents.h
  src/ilinuxevents.cpp

  src/linuxevents.h
  src/linuxevents.cpp
)

target_include_directories("linuxevents" PRIVATE
  include
)

target_include_directories("linuxevents" SYSTEM INTERFACE
  include
)

add_subdirectory("bpf")

target_link_libraries("linuxevents"
  PRIVATE
    "linuxevents_cxx_settings"

  PUBLIC
    "ebpf"
    "error"
    "utils"
    "linuxevents_bpf_probes"
)

target_compile_definitions("linuxevents" PUBLIC
  LINUXEVENTS_VERSION="${LINUXEVENTS_VERSION}"
  LLVM_MAJOR_VERSION="${LLVM_MAJOR_VERSION}"
)
