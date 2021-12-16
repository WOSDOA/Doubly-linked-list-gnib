include ksamd64.inc
EXTERNDEF ?Te@rdtable@CryptoPP@@3PA_KA:FAR
EXTERNDEF ?g_cacheLineSize@CryptoPP@@3IA:FAR
EXTERNDEF ?SHA256_K@CryptoPP@@3QBIB:FAR
.CODE

    ALIGN   8
Baseline_Add	PROC
	lea		rdx, [rdx+8*rcx]
	lea		r8, [r8+8*rcx]
	lea		r9, [r9+8*rcx]
	neg		rcx					; rcx is negative index
	jz		$1@Baseline_Add
	mov		rax,[r8+8*rcx]
	add		rax,[r9+8*rcx]
	mov		[rdx+8*rcx],rax
$0@Baseline_Add:
	mov		rax,[r8+8*rcx+8]
	adc		rax,[r9+8*rcx+8]
	mov		[rdx+8*rcx+8],rax
	lea		rcx,[rcx+2]			; advance index, avoid inc which causes slowdown on Intel Core 2
	jrcxz	$1@Baseline_Add		; loop until rcx overflows and becomes zero
	mov		rax,[r8+8*rcx]
	adc		rax,[r9+8*rcx]
	mov		[rdx+8*rcx],rax
	jmp		$0@Baseline_Add
$1@Baseline_Add:
	mov		rax, 0
	adc		rax, rax			; store carry into rax (return result register)
	ret
Baseline_Add ENDP

    ALIGN   8
Baseline_Sub	PROC
	lea		rdx, [rdx+8*rcx]
	lea		r8, [r8+8*rcx]
	lea		r9, [r9+8*rcx]
	neg		rcx					; rcx is negative index
	jz		$1@Baseline_Sub
	mov		rax,[r8+8*rcx]
	sub		rax,[r9+8*rcx]
	mov		[rdx+8*rcx],rax
$0@Baseline_Sub:
	mov		rax,[r8+8*rcx+8]
	sbb		rax,[r9+8*rcx+8]
	mov		[rdx+8*rcx+8],rax
	lea		rcx,[rcx+2]			; advance index, avoid inc which causes slowdown on Intel Core 2
	jrcxz	$1@Baseline_Sub		; loop until rcx overflows and becomes zero
	mov		rax,[r8+8*rcx]
	sbb		rax,[r9+8*rcx]
	mov		[rdx+8*rcx],rax
	jmp		$0@Baseline_Sub
$1@Baseline_Sub:
	mov		rax, 0
	adc		rax, rax			; store carry into rax (return result register)

	ret
Baseline_Sub ENDP

ALIGN   8
Rijndael_Enc_AdvancedProcessBlocks	PROC FRAME
rex_push_reg rsi
push_reg rdi
push_reg rbx
push_reg r12
.endprolog
mov r8, rcx
mov r11, ?Te@rdtable@CryptoPP@@3PA_KA
mov edi, DWORD PTR [?g_cacheLineSize@CryptoPP@@3IA]
mov rsi, [(r8+16*19)]
mov rax, 16
and rax, rsi
movdqa xmm3, XMMWORD PTR [rdx+16+rax]
movdqa [(r8+16*12)], xmm3
lea rax, [rdx+rax+2*16]
sub rax, rsi
label0:
movdqa xmm0, [rax+rsi]
movdqa XMMWORD PTR [(r8+0)+rsi], xmm0
add rsi, 16
cmp rsi, 16*12
jl label0
movdqa xmm4, [rax+rsi]
movdqa xmm1, [rdx]
mov r12d, [rdx+4*4]
mov ebx, [rdx+5*4]
mov ecx, [rdx+6*4]
mov edx, [rdx+7*4]
xor rax, rax
label9:
mov esi, [r11+rax]
add rax, rdi
mov esi, [r11+rax]
add rax, rdi
mov esi, [r11+rax]
add rax, rdi
mov esi, [r11+rax]
add rax, rdi
cmp rax, 2048
jl label9
lfence
test DWORD PTR [(r8+16*18+8)], 1
jz label8
mov rsi, [(r8+16*14)]
movdqu xmm2, [rsi]
pxor xmm2, xmm1
psrldq xmm1, 14
movd eax, xmm1
mov al, BYTE PTR [rsi+15]
mov r10d, eax
movd eax, xmm2
psrldq xmm2, 4
movd edi, xmm2
psrldq xmm2, 4
movzx esi, al
xor r12d, DWORD PTR [r11+8*rsi+(((0+3) MOD (4))+1)]
movzx esi, ah
xor edx, DWORD PTR [r11+8*rsi+(((1+3) MOD (4))+1)]
shr eax, 16
movzx esi, al
xor ecx, DWORD PTR [r11+8*rsi+(((2+3) MOD (4))+1)]
movzx esi, ah
xor ebx, DWORD PTR [r11+8*rsi+(((3+3) MOD (4))+1)]
mov eax, edi
movd edi, xmm2
psrldq xmm2, 4
movzx esi, al
xor ebx, DWORD PTR [r11+8*rsi+(((0+3) MOD (4))+1)]
movzx esi, ah
xor r12d, DWORD PTR [r11+8*rsi+(((1+3) MOD (4))+1)]
shr eax, 16
movzx esi, al
xor edx, DWORD PTR [r11+8*rsi+(((2+3) MOD (4))+1)]
movzx esi, ah
xor ecx, DWORD PTR [r11+8*rsi+(((3+3) MOD (4))+1)]
mov eax, edi
movd edi, xmm2
movzx esi, al
xor ecx, DWORD PTR [r11+8*rsi+(((0+3) MOD (4))+1)]
movzx esi, ah
xor ebx, DWORD PTR [r11+8*rsi+(((1+3) MOD (4))+1)]
shr eax, 16
movzx esi, al
xor r12d, DWORD PTR [r11+8*rsi+(((2+3) MOD (4))+1)]
movzx esi, ah
xor edx, DWORD PTR [r11+8*rsi+(((3+3) MOD (4))+1)]
mov eax, edi
movzx esi, al
xor edx, DWORD PTR [r11+8*rsi+(((0+3) MOD (4))+1)]
movzx esi, ah
xor ecx, DWORD PTR [r11+8*rsi+(((1+3) MOD (4))+1)]
shr eax, 16
movzx esi, al
xor ebx, DWORD PTR [r11+8*rsi+(((2+3) MOD (4))+1)]
psrldq xmm2, 3
mov eax, [(r8+16*12)+0*4]
mov edi, [(r8+16*12)+2*4]
mov r9d, [(r8+16*12)+3*4]
movzx esi, cl
xor r9d, DWORD PTR [r11+8*rsi+(((3+3) MOD (4))+1)]
movzx esi, bl
xor edi, DWORD PTR [r11+8*rsi+(((3+3) MOD (4))+1)]
movzx esi, bh
xor r9d, DWORD PTR [r11+8*rsi+(((2+3) MOD (4))+1)]
shr ebx, 16
movzx esi, bl
xor eax, DWORD PTR [r11+8*rsi+(((1+3) MOD (4))+1)]
movzx esi, bh
mov ebx, DWORD PTR [r11+8*rsi+(((0+3) MOD (4))+1)]
xor ebx, [(r8+16*12)+1*4]
movzx esi, ch
xor eax, DWORD PTR [r11+8*rsi+(((2+3) MOD (4))+1)]
shr ecx, 16
movzx esi, dl
xor eax, DWORD PTR [r11+8*rsi+(((3+3) MOD (4))+1)]
movzx esi, dh
xor ebx, DWORD PTR [r11+8*rsi+(((2+3) MOD (4))+1)]
shr edx, 16
movzx esi, ch
xor edi, DWORD PTR [r11+8*rsi+(((0+3) MOD (4))+1)]
movzx esi, cl
xor ebx, DWORD PTR [r11+8*rsi+(((1+3) MOD (4))+1)]
movzx esi, dl
xor edi, DWORD PTR [r11+8*rsi+(((1+3) MOD (4))+1)]
movzx esi, dh
xor r9d, DWORD PTR [r11+8*rsi+(((0+3) MOD (4))+1)]
movd ecx, xmm2
mov edx, r12d
mov [(r8+0)+3*4], r9d
mov [(r8+0)+0*4], eax
mov [(r8+0)+1*4], ebx
mov [(r8+0)+2*4], edi
jmp label5
label3:
mov r12d, [(r8+16*12)+0*4]
mov ebx, [(r8+16*12)+1*4]
mov ecx, [(r8+16*12)+2*4]
mov edx, [(r8+16*12)+3*4]
label8:
mov rax, [(r8+16*14)]
movdqu xmm2, [rax]
mov rsi, [(r8+16*14)+8]
movdqu xmm5, [rsi]
pxor xmm2, xmm1
pxor xmm2, xmm5
movd eax, xmm2
psrldq xmm2, 4
movd edi, xmm2
psrldq xmm2, 4
movzx esi, al
xor r12d, DWORD PTR [r11+8*rsi+(((0+3) MOD (4))+1)]
movzx esi, ah
xor edx, DWORD PTR [r11+8*rsi+(((1+3) MOD (4))+1)]
shr eax, 16
movzx esi, al
xor ecx, DWORD PTR [r11+8*rsi+(((2+3) MOD (4))+1)]
movzx esi, ah
xor ebx, DWORD PTR [r11+8*rsi+(((3+3) MOD (4))+1)]
mov eax, edi
movd edi, xmm2
psrldq xmm2, 4
movzx esi, al
xor ebx, DWORD PTR [r11+8*rsi+(((0+3) MOD (4))+1)]
movzx esi, ah
xor r12d, DWORD PTR [r11+8*rsi+(((1+3) MOD (4))+1)]
shr eax, 16
movzx esi, al
xor edx, DWORD PTR [r11+8*rsi+(((2+3) MOD (4))+1)]
movzx esi, ah
xor ecx, DWORD PTR [r11+8*rsi+(((3+3) MOD (4))+1)]
mov eax, edi
movd edi, xmm2
movzx esi, al
xor ecx, DWORD PTR [r11+8*rsi+(((0+3) MOD (4))+1)]
movzx esi, ah
xor ebx, DWORD PTR [r11+8*rsi+(((1+3) MOD (4))+1)]
shr eax, 16
movzx esi, al
xor r12d, DWORD PTR [r11+8*rsi+(((2+3) MOD (4))+1)]
movzx esi, ah
xor edx, DWORD PTR [r11+8*rsi+(((3+3) MOD (4))+1)]
mov eax, edi
movzx esi, al
xor edx, DWORD PTR [r11+8*rsi+(((0+3) MOD (4))+1)]
movzx esi, ah
xor ecx, DWORD PTR [r11+8*rsi+(((1+3) MOD (4))+1)]
shr eax, 16
movzx esi, al
xor ebx, DWORD PTR [r11+8*rsi+(((2+3) MOD (4))+1)]
movzx esi, ah
xor r12d, DWORD PTR [r11+8*rsi+(((3+3) MOD (4))+1)]
mov eax, r12d
add r8, [(r8+16*19)]
add r8, 4*16
jmp label2
label1:
mov ecx, r10d
mov edx, r12d
mov eax, [(r8+0)+0*4]
mov ebx, [(r8+0)+1*4]
xor cl, ch
and rcx, 255
label5:
add r10d, 1
xor edx, DWORD PTR [r11+rcx*8+3]
movzx esi, dl
xor ebx, DWORD PTR [r11+8*rsi+(((3+3) MOD (4))+1)]
movzx esi, dh
mov ecx, DWORD PTR [r11+8*rsi+(((2+3) MOD (4))+1)]
shr edx, 16
xor ecx, [(r8+0)+2*4]
movzx esi, dh
xor eax, DWORD PTR [r11+8*rsi+(((0+3) MOD (4))+1)]
movzx esi, dl
mov edx, DWORD PTR [r11+8*rsi+(((1+3) MOD (4))+1)]
xor edx, [(r8+0)+3*4]
add r8, [(r8+16*19)]
add r8, 3*16
jmp label4
label2:
mov r9d, [(r8+0)-4*16+3*4]
mov edi, [(r8+0)-4*16+2*4]
movzx esi, cl
xor r9d, DWORD PTR [r11+8*rsi+(((3+3) MOD (4))+1)]
mov cl, al
movzx esi, ah
xor edi, DWORD PTR [r11+8*rsi+(((2+3) MOD (4))+1)]
shr eax, 16
movzx esi, bl
xor edi, DWORD PTR [r11+8*rsi+(((3+3) MOD (4))+1)]
movzx esi, bh
xor r9d, DWORD PTR [r11+8*rsi+(((2+3) MOD (4))+1)]
shr ebx, 16
movzx esi, al
xor r9d, DWORD PTR [r11+8*rsi+(((1+3) MOD (4))+1)]
movzx esi, ah
mov eax, DWORD PTR [r11+8*rsi+(((0+3) MOD (4))+1)]
movzx esi, bl
xor eax, DWORD PTR [r11+8*rsi+(((1+3) MOD (4))+1)]
movzx esi, bh
mov ebx, DWORD PTR [r11+8*rsi+(((0+3) MOD (4))+1)]
movzx esi, ch
xor eax, DWORD PTR [r11+8*rsi+(((2+3) MO