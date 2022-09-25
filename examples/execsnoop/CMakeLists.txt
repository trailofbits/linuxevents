#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.14.6)

add_executable("execsnoop"
  src/main.cpp
)

target_link_libraries("execsnoop"
  PRIVATE
    "linuxevents_cxx_settings"
    "linuxevents"
)
