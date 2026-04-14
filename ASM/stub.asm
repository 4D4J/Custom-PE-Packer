bits 64
default rel

config_magic:        dq 0xDEADBEEF
config_num_sections: db 0
config_xor_key:      db 0 
                     dw 0 ; padding for alignment
config_original_oep: dd 0
config_image_base:   dq 0
config_import_rva:   dd 0
config_import_size:  dd 0
config_reloc_rva:    dd 0
config_reloc_size:   dd 0
                     dq 0 ; padding for alignment
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


    ; get the ImageBase from the PEB
    mov rax, qword [gs:60h]
    mov r12, qword [rax + 10h]

    ; find the kernel32.dll 
    mov rbx, qword [rax + 18h]
    lea rbx, [rbx + 20h]
    mov rbx, qword [rbx]
    mov rbx, qword [rbx]
    mov rbx, qword [rbx]
    mov r13, qword [rbx + 20h]         ; r13 = kernel32.dll DllBase

    ; get GetProcAddress and LoadLibraryA in kernel32.dll

    ; get GetProcAddress
    mov rdi, r13                       ; rdi = kernel32.dll DllBase
    lea rsi, [str_GetProcAddress]
    call get_export
    mov r14, rax                       ; r14 = GetProcAddress
    ; get LoadLibraryA
    mov rdi, r13                       ; rdi = kernel32.dll DllBase
    lea rsi, [str_LoadLibraryA]
    call get_export
    mov r15, rax                       ; r15 = LoadLibraryA

    ; decrypt memory section using XOR
    call decrypt_all_sections

    ; get the IAT of the decrypted PE
    call resolve_imports

    call apply_relocations

    mov  eax, dword [rel config_original_oep]  
    movsxd rax, eax 
    add  rax, r12 

    add  rsp, 40h
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rsi
    pop  rdi
    pop  rbx
    pop  rbp

    jmp  rax


get_export:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    push rdx
    push rdi
    push rsi
    push r8
    push r9
    sub  rsp, 28h

    mov eax, dword [rdi + 3Ch]
    add rax, rdi

    mov eax, dword [rax + 18h + 70h]
    test eax, eax
    jz .not_found

    mov r8, rdi
    add r8, rax 
    mov [rsp + 20h], r8 

    mov ecx, dword [r8 + 18h]  
    test ecx, ecx
    jz .not_found

    mov eax, dword [r8 + 20h] 
    add rax, rdi 
    mov r9d, dword [r8 + 24h] 
    add r9, rdi

    xor  rdx, rdx
.search_loop:
    cmp edx, ecx
    jge .not_found

    mov ebx, dword [rax + rdx*4]
    add rbx, rdi

    push rax
    push rcx
    push rdx
    push r9
    call strcmp_ascii
    mov r11, rax
    pop r9
    pop rdx
    pop rcx
    pop rax
    test r11, r11
    jz .found

    inc rdx
    jmp .search_loop

.found:
    movzx rbx, word [r9 + rdx*2]

    mov r8, [rsp + 20h]
    mov eax, dword [r8 + 1Ch]
    add rax, rdi
    mov eax, dword [rax + rbx*4]
    add rax, rdi

    jmp  .done

.not_found:
    xor  rax, rax
.done:
    add rsp, 28h
    pop r9
    pop r8
    pop rsi
    pop rdi
    pop rdx
    pop rcx
    pop rbx
    pop rbp
    ret


strcmp_ascii:
    push rcx
    push rdx
    mov  rcx, rbx 
    mov  rdx, rsi 
.cmp_loop:
    movzx eax, byte [rcx]
    movzx r8d, byte [rdx]
    cmp al, r8b
    jne .cmp_ne
    test al, al 
    jz .cmp_eq
    inc rcx
    inc rdx
    jmp .cmp_loop
.cmp_eq:
    xor eax, eax
    jmp .cmp_done
.cmp_ne:
    mov eax, 1 
.cmp_done:
    pop rdx
    pop rcx
    ret


;function decrypt_all_sections
decrypt_all_sections:
    push rbx
    push rcx
    push rdx
    push r8

    movzx rcx, byte [rel config_num_sections]
    test rcx, rcx
    jz   .done

    lea  rbx, [rel config_sections]
    xor  rdx, rdx
.sect_loop:
    cmp rdx, rcx
    jge .done

    mov r8d, dword [rbx + rdx*8]
    mov r9d, dword [rbx + rdx*8 + 4]

    mov rax, r12
    add rax, r8

    mov rdi, rax
    mov rsi, r9
    push rcx
    push rdx
    movzx edx, byte [rel config_xor_key]
    call decrypt_xor
    pop rdx
    pop rcx

    inc rdx
    jmp .sect_loop
.done:
    pop r8
    pop rdx
    pop rcx
    pop rbx
    ret


; function decrypt XOR
decrypt_xor:
    test rsi, rsi
    jz .done
    xor rcx, rcx 
.xor_loop:
    cmp rcx, rsi
    jge .done
    xor byte [rdi + rcx], dl
    inc rcx
    jmp .xor_loop
.done:
    ret


; fix imports function
resolve_imports:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    push rdi
    push rsi
    push r8
    push r9
    sub rsp, 48h

    mov ecx, dword [rel config_import_rva]
    test ecx, ecx
    jz .done 

    lea rbx, [r12 + rcx]
.next_descriptor:
    mov eax, dword [rbx + 0Ch] 
    test eax, eax
    jz .done


    add rax, r12
    mov rcx, rax
    call r15
    mov [rsp + 20h], rax           

    mov edi, dword [rbx + 10h]
    add rdi, r12
    mov esi, dword [rbx + 00h]
    test esi, esi
    jnz .use_int
    mov esi, edi
.use_int:
    add  rsi, r12
.next_thunk:
    mov r8, qword [rsi]
    test r8, r8
    jz .thunk_done

    bt r8, 63
    jc .import_by_ordinal
.import_by_name:
    mov  eax, r8d 
    add  rax, r12 
    add  rax, 2 
    mov rcx, [rsp + 20h] 
    mov rdx, rax 
    call r14 
    jmp .store_address
.import_by_ordinal:
    movzx rcx, r8w 
    mov rcx, [rsp + 20h] 
    movzx rdx, r8w
    call r14 
.store_address:
    mov qword [rdi], rax
    add rsi, 8 
    add rdi, 8  
    jmp .next_thunk
.thunk_done:
    add rbx, 14h
    jmp .next_descriptor
.done:
    add rsp, 48h
    pop r9
    pop r8
    pop rsi
    pop rdi
    pop rcx
    pop rbx
    pop rbp
    ret


; relocation function
apply_relocations:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9

    mov rax, qword [rel config_image_base]
    mov r9, r12 
    sub r9, rax 

    test r9, r9
    jz .done

    mov  ecx, dword [rel config_reloc_rva]
    test ecx, ecx
    jz   .done

    lea rbx, [r12 + rcx]
    mov edx, dword [rel config_reloc_size] 
    xor rdi, rdi 
.next_block:
    cmp edi, edx
    jge .done

    mov ecx, dword [rbx + 4]
    test ecx, ecx
    jz .done 

    mov rsi, rcx
    sub rsi, 8
    shr rsi, 1 

    mov  r8d, dword [rbx + 0] 
    add  r8, r12    

    lea  rax, [rbx + 8]   
    xor  r10, r10  
.next_entry:
    cmp r10, rsi
    jge .block_done

    movzx r11, word [rax + r10*2] 
    mov rcx, r11
    shr rcx, 12 
    and r11, 0FFFh

    cmp  ecx, 10
    jne  .skip_entry

    add  r11, r8
    add  qword [r11], r9 
.skip_entry:
    inc r10
    jmp .next_entry
.block_done:
    mov ecx, dword [rbx + 4] 
    add edi, ecx
    add rbx, rcx
    jmp .next_block
.done:
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rbp
    ret


str_GetProcAddress: db "GetProcAddress", 0
str_LoadLibraryA: db "LoadLibraryA", 0