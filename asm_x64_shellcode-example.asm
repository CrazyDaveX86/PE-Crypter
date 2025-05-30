BITS 64
DEFAULT REL

%define OFF_OEP_RVA  0
%define OFF_DEC_KEY  4
%define OFF_HOOK_MARKER 5
%define OFF_TEXT_RVA 9
%define OFF_TEXT_VSZ 13
%define OFF_RDATA_RVA 17
%define OFF_RDATA_VSZ 21
%define OFF_DATA_RVA 25
%define OFF_DATA_VSZ 29

%define WINAPI_GetModuleHandleA_OFFSET 0
%define WINAPI_LoadLibraryA_OFFSET     8
%define WINAPI_GetProcAddress_OFFSET   16
%define WINAPI_VirtualProtect_OFFSET   24
%define SIZEOF_WINAPI_POINTERS         32

%define PAGE_READWRITE          0x04
%define PAGE_EXECUTE_READWRITE  0x40

section .text
global _start
_start:
    push rbp
    mov rbp, rsp
    sub rsp, 80
    call get_rip_label
get_rip_label:
    pop r12
    sub r12, (get_rip_label - _start)

    lea rdi, [r12 + (shellcode_end - _start)]
    lea r11, [rbp - 16 - SIZEOF_WINAPI_POINTERS]

    mov rax, gs:[0x60]
    mov rax, [rax + 0x18]
    mov r15, [rax + 0x20]
    mov rbx, rax

find_kernel32_loop:
    mov rcx, [r15 + 0x60]
    movzx edx, word [r15 + 0x58]
    cmp dx, 24
    jne next_module_in_peb_for_compare
    mov ax, word [rcx]
    cmp ax, 0x004B
    je check_e_char_k32
    cmp ax, 0x006B
    jne next_module_in_peb_for_compare
check_e_char_k32:
    mov ax, word [rcx + 2]
    cmp ax, 0x0065
    je check_r_char_k32
    cmp ax, 0x0045
    jne next_module_in_peb_for_compare
check_r_char_k32:
    mov ax, word [rcx + 4]
    cmp ax, 0x0072
    je check_n_char_k32
    cmp ax, 0x0052
    jne next_module_in_peb_for_compare
check_n_char_k32:
    mov ax, word [rcx + 6]
    cmp ax, 0x006E
    je check_e2_char_k32
    cmp ax, 0x004E
    jne next_module_in_peb_for_compare
check_e2_char_k32:
    mov ax, word [rcx + 8]
    cmp ax, 0x0065
    jne next_module_in_peb_for_compare
    mov ax, word [rcx + 10]
    cmp ax, 0x006C
    jne next_module_in_peb_for_compare
    mov ax, word [rcx + 12]
    cmp ax, 0x0033
    jne next_module_in_peb_for_compare
    mov ax, word [rcx + 14]
    cmp ax, 0x0032
    jne next_module_in_peb_for_compare
    mov ax, word [rcx + 16]
    cmp ax, 0x002E
    jne next_module_in_peb_for_compare
    mov ax, word [rcx + 18]
    cmp ax, 0x0064
    jne next_module_in_peb_for_compare
    mov ax, word [rcx + 20]
    cmp ax, 0x006C
    jne next_module_in_peb_for_compare
    mov ax, word [rcx + 22]
    cmp ax, 0x006C
    jne next_module_in_peb_for_compare
    mov r14, [r15 + 0x30]
    jmp found_kernel32_base
next_module_in_peb_for_compare:
next_module_in_peb:
    mov r15, [r15]
    cmp r15, [rbx + 0x20]
    je kernel32_not_found_error
    jmp find_kernel32_loop
kernel32_not_found_error:
    xor r14, r14
found_kernel32_base:
    test r14, r14
    jz critical_api_failure
    mov rdx, r14
    call find_get_proc_address_from_module
    mov [r11 + WINAPI_GetProcAddress_OFFSET], rax
    test rax, rax
    jz critical_api_failure
    mov rcx, r14
    lea rdx, [r12 + (str_GetModuleHandleA - _start)]
    call [r11 + WINAPI_GetProcAddress_OFFSET]
    mov [r11 + WINAPI_GetModuleHandleA_OFFSET], rax
    test rax, rax
    jz critical_api_failure
    mov rcx, r14
    lea rdx, [r12 + (str_LoadLibraryA - _start)]
    call [r11 + WINAPI_GetProcAddress_OFFSET]
    mov [r11 + WINAPI_LoadLibraryA_OFFSET], rax
    test rax, rax
    jz critical_api_failure
    mov rcx, r14
    lea rdx, [r12 + (str_VirtualProtectA - _start)]
    call [r11 + WINAPI_GetProcAddress_OFFSET]
    mov [r11 + WINAPI_VirtualProtect_OFFSET], rax
    test rax, rax
    jz critical_api_failure
    xor rcx, rcx
    call [r11 + WINAPI_GetModuleHandleA_OFFSET]
    mov r13, rax
    movzx ebx, byte [rdi + OFF_DEC_KEY]

    mov esi, [rdi + OFF_TEXT_RVA]
    mov ecx, [rdi + OFF_TEXT_VSZ]
    test ecx, ecx
    jz skip_text_decryption
    lea r8, [r13 + rsi]
    push rdi
    mov rcx, r8
    mov edx, dword [rdi + OFF_TEXT_VSZ]
    mov r8d, PAGE_EXECUTE_READWRITE
    lea r9, [rbp - 8]
    call [r11 + WINAPI_VirtualProtect_OFFSET]
    pop rdi
    test rax, rax
    jz critical_api_failure
    mov esi, [rdi + OFF_TEXT_RVA]
    mov ecx, [rdi + OFF_TEXT_VSZ]
    lea r8, [r13 + rsi]
    call decrypt_section_loop
    push rdi
    mov esi, [rdi + OFF_TEXT_RVA]
    lea rcx, [r13 + rsi]
    mov edx, dword [rdi + OFF_TEXT_VSZ]
    mov r8d, [rbp - 8]
    lea r9, [rbp - 40]
    call [r11 + WINAPI_VirtualProtect_OFFSET]
    pop rdi
    test rax, rax

skip_text_decryption:
    mov esi, [rdi + OFF_RDATA_RVA]
    mov ecx, [rdi + OFF_RDATA_VSZ]
    test ecx, ecx
    jz skip_rdata_decryption
    lea r8, [r13 + rsi]
    push rdi
    mov rcx, r8
    mov edx, dword [rdi + OFF_RDATA_VSZ]
    mov r8d, PAGE_READWRITE
    lea r9, [rbp - 24]
    call [r11 + WINAPI_VirtualProtect_OFFSET]
    pop rdi
    test rax, rax
    jz critical_api_failure
    mov esi, [rdi + OFF_RDATA_RVA]
    mov ecx, [rdi + OFF_RDATA_VSZ]
    lea r8, [r13 + rsi]
    call decrypt_section_loop
    push rdi
    mov esi, [rdi + OFF_RDATA_RVA]
    lea rcx, [r13 + rsi]
    mov edx, dword [rdi + OFF_RDATA_VSZ]
    mov r8d, [rbp - 24]
    lea r9, [rbp - 40]
    call [r11 + WINAPI_VirtualProtect_OFFSET]
    pop rdi
    test rax, rax 

skip_rdata_decryption:
    mov esi, [rdi + OFF_DATA_RVA]
    mov ecx, [rdi + OFF_DATA_VSZ]
    test ecx, ecx
    jz skip_data_decryption
    lea r8, [r13 + rsi]
    push rdi
    mov rcx, r8
    mov edx, dword [rdi + OFF_DATA_VSZ]
    mov r8d, PAGE_READWRITE
    lea r9, [rbp - 32]
    call [r11 + WINAPI_VirtualProtect_OFFSET]
    pop rdi
    test rax, rax
    jz critical_api_failure
    mov esi, [rdi + OFF_DATA_RVA]
    mov ecx, [rdi + OFF_DATA_VSZ]
    lea r8, [r13 + rsi]
    call decrypt_section_loop
    push rdi
    mov esi, [rdi + OFF_DATA_RVA]
    lea rcx, [r13 + rsi]
    mov edx, dword [rdi + OFF_DATA_VSZ]
    mov r8d, [rbp - 32]
    lea r9, [rbp - 40]
    call [r11 + WINAPI_VirtualProtect_OFFSET]
    pop rdi
    test rax, rax 

skip_data_decryption:
    mov r10, r13
    mov eax, dword [r13 + 0x3C]
    add r10, rax
    mov eax, [r10 + 0x90 + 4]
    test eax, eax
    jz no_imports_or_oep_epilogue
    mov esi, [r10 + 0x90]
    add rsi, r13
    push rdi    
    push r12    
    push r13    
    push r10    
    mov rcx, rsi
    mov edx, eax
    mov r8d, PAGE_READWRITE
    lea r9, [rbp - 16]
    call [r11 + WINAPI_VirtualProtect_OFFSET]
    test rax, rax
    jz iat_vp_failed

iat_loop_dll:
    mov eax, [rsi + 0xC]
    test eax, eax
    jz all_imports_processed_restore_iat_protection
    add rax, r13
    mov rcx, rax
    call [r11 + WINAPI_LoadLibraryA_OFFSET]
    mov r10, rax 
    test r10, r10
    jz next_dll_entry
    mov r9, [rsi + 0x10]
    add r9, r13
iat_loop_func_for_dll:
    mov r8, [r9]
    test r8, r8
    jz next_dll_entry
    mov rcx, r10
    bt r8, 63
    jc import_by_ordinal_path
import_by_name_path:
    mov rax, r13
    add r8, rax
    add r8, 2
    mov rdx, r8
    call [r11 + WINAPI_GetProcAddress_OFFSET]
    jmp store_resolved_function_addr

import_by_ordinal_path:
    and r8, 0xFFFF
    mov rdx, r8
    call [r11 + WINAPI_GetProcAddress_OFFSET]
store_resolved_function_addr:
    test rax, rax
    jz function_resolve_failed
    mov [r9], rax
function_resolve_failed:
    add r9, 8
    jmp iat_loop_func_for_dll
next_dll_entry:
    add rsi, 20
    jmp iat_loop_dll

all_imports_processed_restore_iat_protection:
    mov r13, qword [rsp + 0x10] 
    mov r10, qword [rsp + 0x18] 
    mov esi, dword [r10 + 0x90]
    mov eax, dword [r10 + 0x90 + 4]
    add rsi, r13
    mov rcx, rsi
    mov edx, eax
    mov r8d, dword [rbp - 16]
    lea r9, [rbp - 40]
    call [r11 + WINAPI_VirtualProtect_OFFSET]
    pop r10 
    pop r13 
    pop r12 
    pop rdi 
    jmp no_imports_or_oep_epilogue

iat_vp_failed:
    pop r10
    pop r13
    pop r12
    pop rdi
    jmp critical_api_failure

no_imports_or_oep_epilogue:
    mov eax, [rdi + OFF_OEP_RVA]
    add rax, r13
    mov rsp, rbp
    pop rbp
    jmp rax

critical_api_failure:
    hlt

decrypt_section_loop:
    test ecx, ecx
    jz decrypt_done_label
    xor byte [r8], bl
    inc r8
    dec ecx
    jmp decrypt_section_loop
decrypt_done_label:
    ret

find_get_proc_address_from_module:
    push rdi
    push rsi
    push rbx
    push rcx
    push r8
    push r9
    push r10
    mov rbx, rdx
    mov eax, [rbx + 0x3C]
    add rax, rbx
    mov edi, [rax + 0x88]
    add rdi, rbx
    mov ecx, [rdi + 0x18]
    mov r10d, [rdi + 0x20]
    add r10, rbx
    mov r9d, [rdi + 0x24]
    add r9, rbx
    mov r8d, [rdi + 0x1C]
    add r8, rbx
find_gpa_loop_label:
    jecxz gpa_not_found_label
    dec ecx
    mov esi, [r10 + rcx*4]
    add rsi, rbx
    cmp dword [rsi],     0x50746547
    jne find_gpa_loop_label
    cmp dword [rsi+4],   0x41636F72
    jne find_gpa_loop_label
    cmp dword [rsi+8],   0x65726464
    jne find_gpa_loop_label
    cmp word  [rsi+12],  0x7373
    jne find_gpa_loop_label
    cmp byte  [rsi+14],  0x00
    jne find_gpa_loop_label
    movzx edx, word [r9 + rcx*2]
    mov eax, [r8 + rdx*4]
    add rax, rbx
    jmp gpa_found_label
gpa_not_found_label:
    xor rax, rax
gpa_found_label:
    pop r10
    pop r9
    pop r8
    pop rcx
    pop rbx
    pop rsi
    pop rdi
    ret

str_LoadLibraryA:      db "LoadLibraryA", 0
str_GetModuleHandleA:  db "GetModuleHandleA", 0
str_VirtualProtectA:   db "VirtualProtectA", 0
shellcode_end:
