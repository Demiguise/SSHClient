include(CTest)

set(TEST_TARGET test)

add_executable(${TEST_TARGET}
  main.cpp
)

add_test(
  NAME ${TEST_TARGET}
  COMMAND ${TEST_TARGET}
)

target_link_libraries(${TEST_TARGET} SSH)

target_include_directories(${TEST_TARGET}
  PRIVATE
    ${PROJECT_SOURCE_DIR}/thirdparty/Catch2/single_include
    ${PROJECT_SOURCE_DIR}/src
)
