set(SRCS
  ssh.cpp
  ssh_impl.cpp
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

set(CMAKE_DEBUG_POSTFIX _d)

add_library(SSH
  ${SRCS}
)

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

set_target_properties(SSH PROPERTIES
  OUTPUT_NAME "ssh"
  ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/lib"
)
