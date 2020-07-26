.intel_syntax noprefix
.text

	.section .rodata
	.global kpayload, _mmap
	.type   kpayload, @object
	.align  4
kpayload:
	.incbin "../kpayload/kpayload.bin"
kpayload_end:
	.global kpayload_size
	.type   kpayload_size, @object
	.align  4
kpayload_size:
	.int    kpayload_end - kpayload

_mmap:
	mov rax, 477
	mov r10, rcx
	syscall
	ret