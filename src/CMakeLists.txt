set(SRCS
  ssh.cpp
  ssh_impl.cpp
  packets.cpp
  mpint.cpp
  name-list.cpp
  kex/kex.cpp
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

set(SSH_Libs
)

#Test executable (To be removed once we're closer to finishing)
add_executable(SSH_HARNESS
  ${SRCS}
  win32_harness.cpp
)

set_target_properties(SSH_HARNESS PROPERTIES
  OUTPUT_NAME "ssh_harness"
  RUNTIME_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/bin"
)

#WolfSSL (Using it for the WolfCrypt library)
set(WOLFSSL_LIB_DIR ${PROJECT_SOURCE_DIR}/thirdparty/wolfssl)
ExternalProject_Add(wolfSSL
  SOURCE_DIR ${WOLFSSL_LIB_DIR}
  GIT_REPOSITORY https://github.com/wolfSSL/wolfssl.git
  GIT_TAG v4.4.0-stable
  GIT_PROGRESS TRUE
  UPDATE_COMMAND ""
  INSTALL_COMMAND ""
  CONFIGURE_COMMAND ""
  BUILD_COMMAND MSBuild /nologo /t:build /p:Configuration=Debug /p:Platform=x64 wolfssl.vcxproj
  BUILD_IN_SOURCE TRUE
)

set(WOLFSSL_INCLUDE_DIR ${WOLFSSL_LIB_DIR})
set(WOLFSSL_LIB ${WOLFSSL_LIB_DIR}/x64/Debug/wolfssl.lib)
list(APPEND SSH_LIBS ${WOLFSSL_LIB})

add_dependencies(SSH_HARNESS wolfSSL)

target_link_libraries(SSH_HARNESS ${SSH_LIBS})

target_include_directories(SSH_HARNESS
  PUBLIC
    ${PROJECT_SOURCE_DIR}/include
  PRIVATE
    ${PROJECT_SOURCE_DIR}/src
    ${WOLFSSL_INCLUDE_DIR}
)

target_compile_definitions(SSH_HARNESS
  PRIVATE
    ${SSH_Common_Defines}
    $<$<CONFIG:DEBUG>:${SSH_Debug_Defines}>
)

target_compile_options(SSH_HARNESS
  PRIVATE
    ${SSH_Common_Options}
    $<$<CONFIG:DEBUG>:${SSH_Debug_Options}>
)

#Library
set(CMAKE_DEBUG_POSTFIX _d)

add_library(SSH
  ${SRCS}
)

set_target_properties(SSH PROPERTIES
  OUTPUT_NAME "ssh"
  ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/lib"
)

add_dependencies(SSH wolfSSL)

target_link_libraries(SSH ${SSH_LIBS})

target_include_directories(SSH
  PUBLIC
    ${PROJECT_SOURCE_DIR}/include
  PRIVATE
    ${PROJECT_SOURCE_DIR}/src
    ${WOLFSSL_INCLUDE_DIR}
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
