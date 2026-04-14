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
