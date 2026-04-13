bit 64
default rel

config_magic:        dq 0xDEADBEEF
config_num_sections: db 0
config_wor_key:      db 0 
                     dw 0
config_original_oep: dd 0
config_image_base:   dq 0
config_import_rva:   dd 0
config_import_size:  dd 0
config_reloc_rva:    dd 0
config_reloc_size:   dd 0
                     dq 0
config_sections:     times (16 * 8) db 0

stub_entry:
    push rbp
    mov rbp, rsp 
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40h

    mov rax, qword [gs:60h]
    mov r12, qword [rax + 10h]


    mov rbx, qword [rax + 18h]    
    lea rbx, [rbx + 20h]           
    mov rbx, qword [rbx]          
    mov rbx, qword [rbx]           
    mov rbx, qword [rbx] 

    mov  r13, qword [rbx + 20h]         ; r13 = kernel32.dll DllBase

    ; get GetProcAddress
    mov rdi, r13
    lea rsi, [str_GetProcAddress]
    call get_export
    mov r14, rax                        ; r14 = GetProcAddress
    ; get LoadLibraryA
    mov rdi, r13
    lea rsi, [str_LoadLibraryA]
    call get_export
    mov r15, rax                        ; r15 = LoadLibraryA



