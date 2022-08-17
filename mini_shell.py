mini_shell = '''
entry:
    lea rsp,[rip - 0x7]
    add rsp,0x2000
    call mini_shell
/* void gets(char*buffer) */
gets:
    push rbp
    mov rbp,rsp

    push rdi                    /*gets buffer*/
    push 0x0                    /*temp buff*/
readByte:
    xor rdi,rdi
    lea rsi,[rsp]               /*read one byte to buffer*/
    mov rdx,1

    xor rax,rax
    syscall

    cmp rax,1
    jne  error

    cmp byte ptr[rsp],0xa
    je getsend 
    mov al,byte ptr[rsp]

    mov rdi,rsp
    add rdi,0x8
    mov rdi,[rdi]

    mov byte ptr [rdi], al

    inc rdi
    mov [rsp + 0x8],rdi         /*rdi++*/
    jmp readByte

getsend:
    mov rdi,[rsp + 0x8]
    mov byte ptr [rdi],0
error:
    leave
    ret

/* void print(char*string) */
print:
    push rbp
    mov rbp,rsp
    push rdi

    call strlen
    mov rdx,rax
    mov rdi,1
    mov rsi,[rsp]

    mov rax,1
    syscall
    leave
    ret
/* int strlen(const char*s) */
strlen:
    push rbx
    xor rax,rax
    
    test rdi,rdi
    je end
loop:
    mov bl,byte ptr [rdi]
    test bl,bl
    je end
    inc rax
    inc rdi    
    jmp loop
end:
    pop rbx
    ret

/* void cat(const char*filepath)*/
cat:
    push r8
    push rbp
    mov rbp,rsp

    /* buffer */
    sub rsp,0x100
    /* open file */
    xor rax,rax
    xor rsi,rsi
    mov rax,2
    syscall
    cmp rax,-1
    je open_failed
    mov r8,rax
/* loop of read*/
loop_read:
    mov rdi,r8
    mov rsi,rsp
    mov rdx,0x100
    
    xor rax,rax
    syscall

    cmp rax,0
    /* read eof or failed*/
    jle open_failed 

    mov rdi,1
    mov rsi,rsp
    mov rdx,rax

    mov rax,1
    syscall

    jmp loop_read
open_failed:
    leave
    pop r8
    ret

/* void ls(const char*dir) */
ls:  
    push r8
    push rbp
    mov rbp,rsp
    /* buffer */
    sub rsp,0x200

    mov rsi,65536
    mov rax,2
    syscall

    cmp rax,-1
    je ls_failed

    mov r8,rax
/* loop read dir */
loop_read_dir:
    mov rdi,r8
    mov rsi,rsp
    mov rdx,0x200

    mov rax,78
    syscall

    cmp rax,0
    jle ls_failed

    /* r9: nRead */
    mov r9,rax      

    /* show infos in buffer */
    xor rcx,rcx
show_file_in_buffer:
    lea rdi,[rsp + rcx + 16]
    xor rax,rax
    mov ax,word ptr [rdi]
    add rcx,rax
    add rdi,2
    push rcx
    call print
    
    /* dir of regular file*/
    mov rcx,[rsp]

    mov al,byte ptr [rsp + rcx + 7]
    cmp al,0x4
    mov rax,0xa
    mov rdx,1
    jne out_split_char
    / * out char '/' */
    mov rax,0xa2f
    inc rdx
out_split_char:
    push rax
    mov rdi,1
    mov rsi,rsp

    mov rax,1
    syscall
    add rsp,8
    pop rcx
    cmp rcx,r9
    
    jb show_file_in_buffer

    /* all file in buffer has been listed */
    jmp loop_read_dir

ls_failed:
    leave 
    pop r8
    ret

mini_shell:
    sub rsp,0x200
    mov dword ptr[rsp],0x242f
loop_exec_cmd:
    /* show current work dir*/
    mov rdi,rsp
    call print
    /* get user's command */
    lea rdi,[rsp + 0x100]
    call gets
    /* switch command */
if_ls:
    mov eax,[rsp + 0x100]
    and eax,0x00ffffff
    cmp eax,0x20736c
    jne if_cat
    
    lea rdi,[rsp + 0x103]
    call ls
    jmp loop_exec_cmd
if_cat:
    mov eax,[rsp + 0x100] 
    and eax,0xffffffff
    cmp eax,0x20746163
    jne loop_exec_cmd
    
    lea rdi,[rsp + 0x104]
    call cat
    jmp loop_exec_cmd

'''
