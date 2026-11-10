cmake_minimum_required(VERSION 3.20)
project(ASmdead C)

set(CMAKE_C_STANDARD 11)

find_program(NASM_EXECUTABLE nasm REQUIRED)

set(STUB_ASM  "${CMAKE_SOURCE_DIR}/ASM/stub.asm")
set(STUB_BIN  "${CMAKE_SOURCE_DIR}/ASM/stub.bin")

add_custom_command(
    OUTPUT  ${STUB_BIN}
    COMMAND ${NASM_EXECUTABLE} -f bin ${STUB_ASM} -o ${STUB_BIN}
    DEPENDS ${STUB_ASM}
    COMMENT "Assemblage du stub (NASM flat binary)"
)

add_custom_target(stub ALL DEPENDS ${STUB_BIN})

add_executable(packer
    packer/packer.c
    packer/pe_utils.c
    packer/crypto.c
)

target_include_directories(packer PRIVATE packer)

add_dependencies(packer stub)

# Small test binary used end-to-end to show the runtime patch:
# unpacked prints "Hello from non-packed", packed prints "Hello from packed".
add_executable(hello_test tests/hello_test.c)
set_target_properties(hello_test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY         "${CMAKE_BINARY_DIR}/Release"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG   "${CMAKE_BINARY_DIR}/Release"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/Release"
)
