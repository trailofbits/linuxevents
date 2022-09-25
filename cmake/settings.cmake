#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

add_library("linuxevents_common_settings" INTERFACE)
target_compile_options("linuxevents_common_settings" INTERFACE
  -Wall
  -pedantic
  -Wconversion
  -Wunused
  -Wshadow
  -fvisibility=hidden
  -Werror
  -Wno-deprecated-declarations
)

set_target_properties("linuxevents_common_settings" PROPERTIES
  INTERFACE_POSITION_INDEPENDENT_CODE
    true
)

if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
  target_compile_options("linuxevents_common_settings" INTERFACE
    -O0
  )

  target_compile_definitions("linuxevents_common_settings" INTERFACE
    DEBUG
  )

else()
  target_compile_options("linuxevents_common_settings" INTERFACE
    -O2
  )

  target_compile_definitions("linuxevents_common_settings" INTERFACE
    NDEBUG
  )
endif()

if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug" OR "${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo")
  target_compile_options("linuxevents_common_settings" INTERFACE
    -g3
  )
else()
  target_compile_options("linuxevents_common_settings" INTERFACE
    -g0
  )
endif()

add_library("linuxevents_cxx_settings" INTERFACE)
target_compile_features("linuxevents_cxx_settings" INTERFACE
  cxx_std_17
)

target_link_libraries("linuxevents_cxx_settings" INTERFACE
  "linuxevents_common_settings"
)

add_library("linuxevents_c_settings" INTERFACE)
target_link_libraries("linuxevents_c_settings" INTERFACE
  "linuxevents_common_settings"
)
