set(SRCS
  ssh.cpp
  ssh_impl.cpp
  packets.cpp
  name-list.cpp
)

set(SSH_Common_Defines
)

set(SSH_Debug_Defines
  _DEBUG
)

set(SSH_Common_Options
)

set(SSH_Debug_Options
)

if (${SSH_Target_Type} STREQUAL "Exe")

  add_executable(SSH
    ${SRCS}
    win32_harness.cpp
  )

  set_target_properties(SSH PROPERTIES
    OUTPUT_NAME "ssh"
    RUNTIME_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/bin"
  )

else()

  set(CMAKE_DEBUG_POSTFIX _d)

  add_library(SSH
    ${SRCS}
  )

  set_target_properties(SSH PROPERTIES
    OUTPUT_NAME "ssh"
    ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/lib"
  )

endif()

target_include_directories(SSH
  PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)

target_compile_definitions(SSH
  PRIVATE
    ${SSH_Common_Defines}
    $<$<CONFIG:DEBUG>:${SSH_Debug_Defines}>
)

target_compile_options(SSH
  PRIVATE
    ${SSH_Common_Options}
    $<$<CONFIG:DEBUG>:${SSH_Debug_Options}>
)
