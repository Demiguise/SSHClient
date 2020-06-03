set(SRCS
  ssh.cpp
)

set(HDRS
  include/ssh.h
)

set(SSH_Common_Defines
)

set(SSH_Debug_Defines
  __DEBUG
)

set(SSH_Common_Options
)

set(SSH_Debug_Options
)

set(CMAKE_DEBUG_POSTFIX _d)

add_library(SSH
  ${SRCS}
  ${HDRS}
)

target_include_directories(SSH
  PUBLIC
    include
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

set_target_properties(SSH PROPERTIES
  OUTPUT_NAME "ssh"
  ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/lib"
)
