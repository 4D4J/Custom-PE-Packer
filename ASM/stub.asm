bits 64
default rel

config_magic:               dq 0xDEADBEEF ; 0x00
config_num_sections:        db 0          ; 0x08
config_xor_key:             db 0          ; 0x09  (only used when algo=0)
config_algo:                db 0          ; 0x0A  0=XOR, 1=AES128CTR
                            db 0          ; 0x0B  padding
config_original_oep:        dd 0          ; 0x0C
config_image_base:          dq 0          ; 0x10
config_import_rva:          dd 0          ; 0x18
config_import_size:         dd 0          ; 0x1C
config_tls_rva:             dd 0          ; 0x20
config_tls_size:            dd 0          ; 0x24
config_hash_getprocaddr:    dd 0          ; 0x28 - DJB2("GetProcAddress")
config_hash_loadlib:        dd 0          ; 0x2C - DJB2("LoadLibraryA")
config_hash_virtualalloc:   dd 0          ; 0x30 - DJB2("VirtualAlloc")
                            dd 0          ; 0x34 padding
                            dq 0          ; 0x38 padding
config_sections:            times (16 * 8) db 0  ; 0x40  (16 entries of {rva,size})
config_aes_key:             times 16 db 0 ; 0xC0  AES-128 master key
config_aes_nonce:           dq 0          ; 0xD0  AES-CTR nonce (64 bits)
                            dq 0          ; 0xD8  padding
config_patch_rva:           dd 0          ; 0xE0  runtime patch target RVA (0 = none)
config_patch_size:          dd 0          ; 0xE4  patch length in bytes (<= 32)
config_patch_bytes:         times 32 db 0 ; 0xE8  bytes to write
                            dq 0          ; 0x108 padding -> STUB_CODE_OFFSET=0x110

stub_entry:
    ; Phase 1: capture [rsp] (BTIT+offset) and pristine RSP before any push.
    mov rax, qword [rsp]
    mov qword [rel legit_bti_cache], rax
    mov qword [rel initial_rsp_cache], rsp

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
    mov r12, qword [rax + 10h]         ; r12 = actual ImageBase (ASLR)

    mov rbx, qword [rax + 18h]
    lea rbx, [rbx + 20h]
    mov rbx, qword [rbx]
    mov rbx, qword [rbx]
    mov rbx, qword [rbx]
    mov r13, qword [rbx + 20h]         ; r13 = kernel32.dll DllBase

    ; Resolve GetProcAddress + LoadLibraryA by DJB2 hash.
    mov rdi, r13
    mov esi, dword [rel config_hash_getprocaddr]
    call get_export
    mov r14, rax                       ; r14 = GetProcAddress

    mov rdi, r13
    mov esi, dword [rel config_hash_loadlib]
    call get_export
    mov r15, rax                       ; r15 = LoadLibraryA

    ; Phase 1b: unwind through BTIT to recover legit_rtl_cache.
    call capture_legit_rtl

    call decrypt_all_sections
    ; Runtime patch (e.g. visible-proof string swap) runs between decrypt
    ; and import resolve: sections are writable plaintext, IAT is still raw.
    call apply_runtime_patch
    call resolve_imports
    ; TLS callbacks run AFTER IAT fix-up (MSVC callbacks need UCRT imports).
    call handle_tls_callbacks

    ; OEP VA = actual_base + config_original_oep.
    mov    eax, dword [rel config_original_oep]
    movsxd rax, eax
    add    rax, r12

    ; Restore callee-saved regs BEFORE Phase 3 (post-pivot the stack is gone).
    add  rsp, 40h
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rsi
    pop  rdi
    pop  rbx
    pop  rbp

    ; Phase 3: pivot onto a fake stack and RET into OEP. rax = OEP VA.
    jmp  spoof_and_jump


; get_export(rdi=DllBase, esi=target_hash) -> rax=func_va (0 if not found)
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

    mov eax, dword [rdi + 3Ch]           ; e_lfanew
    add rax, rdi
    mov eax, dword [rax + 18h + 70h]     ; DataDirectory[EXPORT].VA (opt+0x70)
    test eax, eax
    jz .not_found

    mov r8, rdi
    add r8, rax
    mov [rsp + 20h], r8                  ; save ExportDir* on stack

    mov ecx, dword [r8 + 18h]            ; NumberOfNames
    test ecx, ecx
    jz .not_found

    mov eax, dword [r8 + 20h]            ; AddressOfNames (RVA[])
    add rax, rdi                         ; rax = &ENT[0]
    mov r9d, dword [r8 + 24h]            ; AddressOfNameOrdinals (RVA)
    add r9, rdi                          ; r9 = &EOT[0]

    xor rdx, rdx                         ; i = 0
.search_loop:
    cmp edx, ecx
    jge .not_found

    mov ebx, dword [rax + rdx*4]         ; ENT[i] = name RVA
    add rbx, rdi                         ; rbx = &name

    push rax
    push rcx
    push rdx
    push r8
    push r9
    mov rcx, rbx                         ; djb2_hash(name)
    call djb2_hash
    cmp eax, esi                         ; hash match ? (pop below doesn't alter flags)
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rax
    je .found

    inc rdx
    jmp .search_loop

.found:
    movzx rbx, word [r9 + rdx*2]         ; ordinal = EOT[i]
    mov r8, [rsp + 20h]                  ; ExportDir*
    mov eax, dword [r8 + 1Ch]            ; AddressOfFunctions (RVA)
    add rax, rdi
    mov eax, dword [rax + rbx*4]         ; func RVA
    add rax, rdi                         ; func VA
    jmp .done

.not_found:
    xor rax, rax
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


; djb2_hash(rcx=name) -> eax=hash32. h=5381; h = h*33 + c per byte.
djb2_hash:
    mov eax, 5381
.loop:
    movzx r11d, byte [rcx]
    test r11d, r11d
    jz .done
    mov r10d, eax
    shl r10d, 5                          ; h * 32
    add r10d, eax                        ; + h -> h*33
    add r10d, r11d                       ; + c
    mov eax, r10d
    inc rcx
    jmp .loop
.done:
    ret


; decrypt_all_sections() - dispatch on config_algo (0=XOR, 1=AES128-CTR).
decrypt_all_sections:
    movzx eax, byte [rel config_algo]
    cmp al, 1
    je decrypt_all_sections_aes

    ; --- XOR path ---
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


; decrypt_xor(rdi=buffer, rsi=size, dl=key) - XOR every byte with dl.
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


; decrypt_all_sections_aes() - AES-128-CTR path. Expands the key once, then
;   iterates sections. Round keys live on our stack (176 B).
decrypt_all_sections_aes:
    push rbp
    mov rbp, rsp
    push rbx
    push r14
    push r15
    sub rsp, 192                        ; 176 round keys + 16 pad (16-align)

    mov rdi, rsp
    call aes128_key_expand              ; fills [rsp .. rsp+175]

    movzx r15, byte [rel config_num_sections]
    test r15, r15
    jz .done

    lea r14, [rel config_sections]
    xor rbx, rbx                        ; section idx
.sect_loop:
    cmp rbx, r15
    jae .done

    mov r8d, dword [r14 + rbx*8]        ; rva
    mov r9d, dword [r14 + rbx*8 + 4]    ; raw size

    lea rdi, [r12 + r8]                 ; data = base + rva
    mov rsi, r9
    mov edx, r8d                        ; counter uses section rva
    mov r8, rsp                         ; round keys
    call decrypt_aes_ctr

    inc rbx
    jmp .sect_loop
.done:
    add rsp, 192
    pop r15
    pop r14
    pop rbx
    pop rbp
    ret


; aes128_key_expand(rdi = &round_keys[11*16])
;   Loads master key from config_aes_key, derives all 11 round keys at rdi.
%macro AES_EXPAND_ROUND 2    ; 1 = round, 2 = rcon
    aeskeygenassist xmm1, xmm0, %2
    call aes128_schedule_step
    movdqu [rdi + %1*16], xmm0
%endmacro

aes128_key_expand:
    movdqu xmm0, [rel config_aes_key]
    movdqu [rdi + 0*16], xmm0
    AES_EXPAND_ROUND 1,  0x01
    AES_EXPAND_ROUND 2,  0x02
    AES_EXPAND_ROUND 3,  0x04
    AES_EXPAND_ROUND 4,  0x08
    AES_EXPAND_ROUND 5,  0x10
    AES_EXPAND_ROUND 6,  0x20
    AES_EXPAND_ROUND 7,  0x40
    AES_EXPAND_ROUND 8,  0x80
    AES_EXPAND_ROUND 9,  0x1B
    AES_EXPAND_ROUND 10, 0x36
    ret


; aes128_schedule_step: xmm0=prev_rk, xmm1=aeskeygen result -> xmm0=next_rk.
aes128_schedule_step:
    pshufd xmm1, xmm1, 0xFF
    movdqa xmm2, xmm0
    pslldq xmm2, 4
    pxor   xmm0, xmm2
    pslldq xmm2, 4
    pxor   xmm0, xmm2
    pslldq xmm2, 4
    pxor   xmm0, xmm2
    pxor   xmm0, xmm1
    ret


; aes128_encrypt_block(xmm0=input, r8=&round_keys[0]) -> xmm0=ciphertext
aes128_encrypt_block:
    pxor       xmm0, [r8 + 0*16]
    aesenc     xmm0, [r8 + 1*16]
    aesenc     xmm0, [r8 + 2*16]
    aesenc     xmm0, [r8 + 3*16]
    aesenc     xmm0, [r8 + 4*16]
    aesenc     xmm0, [r8 + 5*16]
    aesenc     xmm0, [r8 + 6*16]
    aesenc     xmm0, [r8 + 7*16]
    aesenc     xmm0, [r8 + 8*16]
    aesenc     xmm0, [r8 + 9*16]
    aesenclast xmm0, [r8 + 10*16]
    ret


; decrypt_aes_ctr(rdi=data, rsi=size, edx=section_rva, r8=&round_keys[0])
;   Counter block = config_aes_nonce (8B) || section_rva (4B) || block_idx_LE (4B)
decrypt_aes_ctr:
    push rbp
    mov rbp, rsp
    push rbx
    sub rsp, 32                         ; [rsp..15]=counter, [rsp+16..31]=ks tail

    mov rax, qword [rel config_aes_nonce]
    mov qword [rsp],     rax
    mov dword [rsp + 8], edx
    mov dword [rsp + 12], 0

    xor rbx, rbx                        ; byte_offset
    xor r10d, r10d                      ; block_idx
.block_loop:
    cmp rbx, rsi
    jae .done

    mov dword [rsp + 12], r10d
    movdqu xmm0, [rsp]
    call aes128_encrypt_block           ; xmm0 = keystream

    mov r11, rsi
    sub r11, rbx                        ; remaining bytes
    cmp r11, 16
    jb .partial

    movdqu xmm1, [rdi + rbx]
    pxor   xmm0, xmm1
    movdqu [rdi + rbx], xmm0
    add rbx, 16
    inc r10d
    jmp .block_loop

.partial:
    movdqu [rsp + 16], xmm0
    lea rcx, [rdi + rbx]
    xor r9, r9
.tail_loop:
    cmp r9, r11
    jae .done
    mov al, byte [rsp + 16 + r9]
    xor byte [rcx + r9], al
    inc r9
    jmp .tail_loop

.done:
    add rsp, 32
    pop rbx
    pop rbp
    ret


; resolve_imports() - walk IMAGE_IMPORT_DESCRIPTOR[] at config_import_rva,
;   LoadLibraryA (r15) each DLL, GetProcAddress (r14) each import, patch IAT.
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
    mov rcx, [rsp + 20h]               ; rcx = hModule
    movzx rdx, r8w                     ; rdx = ordinal (low 16 bits)
    call r14                           ; GetProcAddress(hModule, (LPCSTR)ordinal)
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


; handle_tls_callbacks() - invoke each TLS callback with DLL_PROCESS_ATTACH.
handle_tls_callbacks:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    sub rsp, 28h

    mov ecx, dword [rel config_tls_rva]
    test ecx, ecx
    jz .done

    mov rbx, r12
    add rbx, rcx                       ; rbx = &IMAGE_TLS_DIRECTORY64

    mov rbx, qword [rbx + 18h]         ; rbx = AddressOfCallBacks (VA)
    test rbx, rbx
    jz .done

.cb_loop:
    mov rax, qword [rbx]               ; cb = *(PIMAGE_TLS_CALLBACK*)rbx
    test rax, rax
    jz .done

    mov rcx, r12                       ; DllHandle = ImageBase
    mov edx, 1                         ; DLL_PROCESS_ATTACH
    xor r8, r8                         ; Reserved = NULL
    call rax

    add rbx, 8
    jmp .cb_loop
.done:
    add rsp, 28h
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rbp
    ret


; apply_runtime_patch() - write config_patch_bytes at (image_base + patch_rva).
;   Both config_patch_rva == 0 and config_patch_size == 0 mean "nothing to do".
;   Called AFTER decrypt_all_sections so the target bytes are plaintext.
apply_runtime_patch:
    mov ecx, dword [rel config_patch_rva]
    test ecx, ecx
    jz .done
    mov edx, dword [rel config_patch_size]
    test edx, edx
    jz .done
    cmp edx, 32
    ja .done

    lea rdi, [r12 + rcx]                ; dst = base + patch_rva
    lea rsi, [rel config_patch_bytes]
    xor rax, rax
.copy_loop:
    cmp rax, rdx
    jae .done
    mov r8b, byte [rsi + rax]
    mov byte [rdi + rax], r8b
    inc rax
    jmp .copy_loop
.done:
    ret


; find_runtime_function(rdi=dll_base, esi=rva) -> rax = RUNTIME_FUNCTION* or NULL
; Linear scan of the Exception Directory for [BeginAddress, EndAddress) ∋ rva.
find_runtime_function:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    push rdx
    push r8
    push r9

    mov eax, dword [rdi + 3Ch]          ; e_lfanew
    lea r8, [rdi + rax]                 ; r8 = NtHeaders

    ; DataDirectory[3] EXCEPTION: NT+0xA0 = sig(4)+file(20)+opt(0x70)+3*8.
    mov eax, dword [r8 + 0A0h]          ; Exception VirtualAddress
    mov ecx, dword [r8 + 0A4h]          ; Exception Size
    test eax, eax
    jz .not_found
    test ecx, ecx
    jz .not_found

    lea rbx, [rdi + rax]                ; rbx = &RUNTIME_FUNCTION[0]
    mov r9d, ecx
    add r9, rbx                         ; r9 = end pointer

    mov rdx, rbx                        ; rdx = iter
.loop:
    cmp rdx, r9
    jae .not_found

    mov eax, dword [rdx]                ; BeginAddress
    cmp esi, eax
    jb .next
    mov eax, dword [rdx + 4]            ; EndAddress
    cmp esi, eax
    jae .next

    ; rva in [Begin, End)
    mov rax, rdx
    jmp .done

.next:
    add rdx, 12                         ; sizeof(RUNTIME_FUNCTION) = 12
    jmp .loop

.not_found:
    xor rax, rax
.done:
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rbx
    pop rbp
    ret


; parse_unwind_info(rcx=UNWIND_INFO*) -> rax = prologue stack delta (or -1).
; Supports PUSH_NONVOL, ALLOC_SMALL/LARGE, PUSH_MACHFRAME, SET_FPREG,
; SAVE_NONVOL[_FAR], SAVE_XMM128[_FAR].
parse_unwind_info:
    push rbp
    mov rbp, rsp
    push rbx
    push rdx
    push rsi
    push rdi
    push r8
    push r9

    movzx r8d, byte [rcx + 2]           ; CountOfCodes
    lea rbx, [rcx + 4]                  ; &UNWIND_CODE[0]
    xor rax, rax                        ; delta = 0
    xor rdi, rdi                        ; i = 0
.loop:
    cmp rdi, r8
    jae .done

    mov r9, rdi
    shl r9, 1                           ; UNWIND_CODE is 2 bytes
    movzx edx, byte [rbx + r9 + 1]      ; byte 1 = UnwindOp:4 | OpInfo:4
    mov esi, edx
    and edx, 0Fh                        ; UnwindOp
    shr esi, 4                          ; OpInfo

    cmp edx, 0
    je .push_nonvol
    cmp edx, 1
    je .alloc_large
    cmp edx, 2
    je .alloc_small
    cmp edx, 3
    je .set_fpreg
    cmp edx, 4
    je .save_nonvol
    cmp edx, 5
    je .save_nonvol_far
    cmp edx, 8
    je .save_xmm128
    cmp edx, 9
    je .save_xmm128_far
    cmp edx, 10
    je .push_machframe
    jmp .fail

.push_nonvol:                           ; op 0: push r64 -> +8 bytes
    add rax, 8
    inc rdi
    jmp .loop

.alloc_large:                           ; op 1: sub rsp, large
    cmp esi, 0
    je .alloc_large_1
    cmp esi, 1
    je .alloc_large_2
    jmp .fail
.alloc_large_1:                         ; info 0: next slot * 8
    mov r9, rdi
    inc r9
    shl r9, 1
    movzx edx, word [rbx + r9]
    shl edx, 3
    add rax, rdx
    add rdi, 2
    jmp .loop
.alloc_large_2:                         ; info 1: next 2 slots = raw bytes
    mov r9, rdi
    inc r9
    shl r9, 1
    mov edx, dword [rbx + r9]
    add rax, rdx
    add rdi, 3
    jmp .loop

.alloc_small:                           ; op 2: (OpInfo+1)*8
    inc esi
    shl esi, 3
    add rax, rsi
    inc rdi
    jmp .loop

.set_fpreg:                             ; op 3: establish FP ; no rsp move here
    inc rdi
    jmp .loop

.save_nonvol:                           ; op 4: 2 slots
    add rdi, 2
    jmp .loop
.save_nonvol_far:                       ; op 5: 3 slots
    add rdi, 3
    jmp .loop
.save_xmm128:                           ; op 8: 2 slots
    add rdi, 2
    jmp .loop
.save_xmm128_far:                       ; op 9: 3 slots
    add rdi, 3
    jmp .loop

.push_machframe:                        ; op 10: interrupt/machine frame
    cmp esi, 0
    je .mf_user
    cmp esi, 1
    je .mf_error
    jmp .fail
.mf_user:
    add rax, 40                         ; 5 * 8
    inc rdi
    jmp .loop
.mf_error:
    add rax, 48                         ; 6 * 8
    inc rdi
    jmp .loop

.fail:
    mov rax, -1
.done:
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rbx
    pop rbp
    ret


; capture_legit_rtl() - unwind one frame through BTIT, store RUTS return
;   address in legit_rtl_cache (0 on failure). Needs r13 = kernel32 DllBase.
capture_legit_rtl:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    push rdi
    push rsi
    push r8
    sub rsp, 28h                        ; shadow + 8 for 16-byte align before CALL

    ; rva = legit_bti_cache - kernel32_base
    mov rax, qword [rel legit_bti_cache]
    sub rax, r13

    mov rdi, r13
    mov esi, eax
    call find_runtime_function
    test rax, rax
    jz .fail

    ; UnwindInfoAddress is at RUNTIME_FUNCTION[+8]
    mov r8d, dword [rax + 8]
    lea rcx, [r13 + r8]                 ; rcx = &UNWIND_INFO
    call parse_unwind_info
    cmp rax, -1
    je .fail

    ; ret_to_RUTS = *(initial_rsp + prologue_delta + 8)
    mov r8, qword [rel initial_rsp_cache]
    add r8, rax
    add r8, 8
    mov rax, qword [r8]
    mov qword [rel legit_rtl_cache], rax
    jmp .done

.fail:
    mov qword [rel legit_rtl_cache], 0
.done:
    add rsp, 28h
    pop r8
    pop rsi
    pop rdi
    pop rcx
    pop rbx
    pop rbp
    ret


; spoof_and_jump(rax=OEP_VA) - NEVER RETURNS
;   VirtualAlloc(1 MiB RW) -> write {bti,rtl,0} near top -> pivot RSP -> ret.
;   Fallback: jmp rax directly (one legit frame deep via the real stack).
spoof_and_jump:
    mov rbx, rax                        ; preserve OEP across our CALLs

    ; Bail before VirtualAlloc if Phase 1 missed a capture (no page leak).
    mov rcx, qword [rel legit_bti_cache]
    test rcx, rcx
    jz .direct_jmp
    mov rdx, qword [rel legit_rtl_cache]
    test rdx, rdx
    jz .direct_jmp

    ; Re-walk PEB -> kernel32 (r13 was clobbered by pop).
    mov rax, qword [gs:60h]
    mov r13, qword [rax + 18h]
    lea r13, [r13 + 20h]
    mov r13, qword [r13]
    mov r13, qword [r13]
    mov r13, qword [r13]
    mov r13, qword [r13 + 20h]          ; r13 = kernel32 DllBase

    sub rsp, 28h                        ; shadow + align (RSP: 8 -> 0)

    mov rdi, r13
    mov esi, dword [rel config_hash_virtualalloc]
    call get_export
    test rax, rax
    jz .unwind_and_fallback

    ; VirtualAlloc(NULL, 0x100000, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
    xor  ecx, ecx
    mov  edx, 0x100000                  ; 1 MiB -- matches a real Win x64 stack
    mov  r8d, 0x3000                    ; MEM_COMMIT | MEM_RESERVE
    mov  r9d, 4                         ; PAGE_READWRITE
    call rax
    test rax, rax
    jz .unwind_and_fallback

    ; Reload captures (rcx/rdx clobbered by CALLs).
    mov rcx, qword [rel legit_bti_cache]
    mov rdx, qword [rel legit_rtl_cache]

    ; fake_top = alloc + 1MiB - 0x100 guard. Layout (grows downward):
    ;   [top-0x08]=0  [top-0x10]=legit_rtl  [top-0x18]=legit_bti
    lea r10, [rax + 0x100000 - 0x100]
    mov qword [r10 - 0x08], 0
    mov qword [r10 - 0x10], rdx
    mov qword [r10 - 0x18], rcx

    ; Pivot: real stack now unreachable to any RBP/RSP walker.
    lea rsp, [r10 - 0x18]

    ; push OEP + ret -> OEP sees [rsp]=legit_bti (perfect post-CALL layout).
    push rbx
    ret

.unwind_and_fallback:
    add rsp, 28h
.direct_jmp:
    jmp rbx


; Call Stack Spoofing caches (filled by Phase 1, consumed by Phase 3).
legit_bti_cache:    dq 0
legit_rtl_cache:    dq 0
initial_rsp_cache:  dq 0