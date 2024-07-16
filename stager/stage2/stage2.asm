[bits 64]

; Save the environment variable pointer (we are assuming no push or pop operations have happened yet)
mov rax, [rsp] ; retrieve argc
add rax, 2 ; skip over null byte at end of argv
lea r14, [rsp+8*rax] ; r14 = envp**

; open("/tmp/x", O_WRONLY | O_CREAT | O_TRUNC, "rwxr--r--")
mov rax, 0x782f706d742f  ; rdi = /tmp/x string
push rax
mov rdi, rsp
mov rax, 2 ; rax = open syscall
mov rsi, 577 ; rsi = O_WRONLY | O_CREAT | O_TRUNC
mov rdx, 484 ; rdx = rwxr--r--
syscall

mov r13, rax ; /tmp/x file descriptor

; Write to file
mov rdx, c_version_end - c_version_start ; rdx = amount of bytes read
mov rax, 1 ; rax = write syscall
mov rdi, r13 ; rdi = /tmp/x file descriptor

; Trick to get a reference to instruction pointer and calculate c_version_start
call fake_func
fake_func:
pop rsi
add rsi, c_version_start - fake_func

syscall

; close(/tmp/x file descriptor)
mov rax, 3 ; rax = close syscall
mov rdi, r13 ; rdi = /tmp/x file descriptor
syscall

; chmod("/tmp/x", "rwxr--r--")
mov rax, 0x782f706d742f  ; rdi = /tmp/x string
push rax
mov rdi, rsp
mov rax, 90 ; rax = chmod syscall
mov rsi, 484 ; rsi = rwxr--r--
syscall

; execve("/tmp/x", { NULL }, { NULL })
mov rax, 59 ; rax = execve syscall
; rdi is already /tmp/x
push 0
mov rsi, rsp ; argv = { NULL }
mov rdx, r14 ; envp = parent envp
syscall

; exit(0)
mov rax, 60
mov rdi, 0
syscall

c_version_start:
incbin "stage2-c.out"
c_version_end: