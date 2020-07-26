#include <ps4.h>

#include "defines.h"
#include "debug.h"
#include "offsets.h"

#define PS4_UPDATE_FULL_PATH "/update/PS4UPDATE.PUP"
#define PS4_UPDATE_TEMP_PATH "/update/PS4UPDATE.PUP.net.temp"

extern char kpayload[];
unsigned payload_size;

int install_payload(struct thread *td, struct install_payload_args* args)
{
	struct ucred* cred;
	struct filedesc* fd;

	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;

	uint8_t* kernel_base = (uint8_t*)(__readmsr(0xC0000082) - XFAST_SYSCALL_addr);
	uint8_t* kernel_ptr = (uint8_t*)kernel_base;
	void** got_prison0 = (void**)&kernel_ptr[PRISON0_addr];
	void** got_rootvnode = (void**)&kernel_ptr[ROOTVNODE_addr];

	uint8_t* payload_data = args->payload_info->buffer;
	size_t payload_size = args->payload_info->size;
	struct payload_header* payload_header = (struct payload_header*)payload_data;


	//uint8_t* payload_buffer = (uint8_t*)&kernel_base[DT_HASH_SEGMENT_addr];

	if (!payload_data || payload_size < sizeof(payload_header) || payload_header->signature != 0x5041594C4F414458ull)
		return -1;

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;

	cred->cr_prison = *got_prison0;
	fd->fd_rdir = fd->fd_jdir = *got_rootvnode;

	// escalate ucred privs, needed for access to the filesystem ie* mounting & decrypting files
	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred

	// sceSblACMgrIsSystemUcred
	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;

	// sceSblACMgrGetDeviceAccessType
	uint64_t *sceProcType = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcType = 0x3801000000000013; // Max access

	// sceSblACMgrHasSceProcessCapability
	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff; // Sce Process

	// Disable write protection
	uint64_t cr0 = readCr0();
	writeCr0(cr0 & ~X86_CR0_WP);

	// debug menu error patches 5.05
//	*(uint32_t *)(kernel_base + debug_menu_error_patch1) = 0;
//	*(uint32_t *)(kernel_base + debug_menu_error_patch2) = 0;

	uint8_t* gKernelBase = kernel_base;
	uint8_t *kmem;
	kmem = (uint8_t*)&gKernelBase[0x66AEB0];
	kmem[0] = 0xB0; 
	kmem[1] = 0x01; 
	kmem[2] = 0xC3; 
	kmem[3] = 0x90;

	// Enable debug rifs 2
	kmem = (uint8_t*)&gKernelBase[0x66AEE0];
	kmem[0] = 0xB0; 
	kmem[1] = 0x01; 
	kmem[2] = 0xC3;
	kmem[3] = 0x90;


	kmem = (uint8_t*)&gKernelBase[0x0041A2D0];
	kmem[0] = 0x31; // xor eax, eax
	kmem[1] = 0xC0; 
	kmem[2] = 0xC3;	// ret

	// Disable pfs checks
	kmem = (uint8_t*)&gKernelBase[0x6A8EB0];
	kmem[0] = 0x31; 
	kmem[1] = 0xC0; 
	kmem[2] = 0xC3; 
	kmem[3] = 0x90;

	kmem = (uint8_t*)&gKernelBase[0x003C1857];
	kmem[0] = 0x41;
	kmem[1] = 0x41;

	// Patch sys_mmap
	kmem = (uint8_t*)&gKernelBase[0x000AB57A];
	kmem[0] = 0x37; // mov     [rbp+var_61], 33h ; '3'
	kmem[3] = 0x37; // mov     sil, 33h ; '3'

	// enable uart output
	//*(uint32_t *)(kernel_base + enable_uart_patch) = 0;

	uint8_t* payload_buffer = (uint8_t*)_mmap(NULL, 0x500000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);

	// install kpayload
	memset(payload_buffer, 0, PAGE_SIZE);
	memcpy(payload_buffer, payload_data, payload_size);

	// Restore write protection
	writeCr0(cr0);

	int (*payload_entrypoint)();
	*((void**)&payload_entrypoint) = (void*)(&payload_buffer[payload_header->entrypoint_offset]);

	return payload_entrypoint();
}

static inline void patch_update(void)
{
	unlink(PS4_UPDATE_FULL_PATH);
	unlink(PS4_UPDATE_TEMP_PATH);

	mkdir(PS4_UPDATE_FULL_PATH, 0777);
	mkdir(PS4_UPDATE_TEMP_PATH, 0777);
}

int _main(struct thread *td) 
{
	int result;

	initKernel();	
	initLibc();

#ifdef DEBUG_SOCKET
	initNetwork();
	initDebugSocket();
#endif

	printfsocket("Starting...\n");

	struct payload_info payload_info;
	payload_info.buffer = (uint8_t *)kpayload;
	payload_info.size = (size_t)payload_size;

	errno = 0;

	result = kexec(&install_payload, &payload_info);
	result = !result ? 0 : errno;
	printfsocket("install_payload: %d\n", result);

	patch_update();

	initSysUtil();
	notify("Welcome to PS4HEN v"VERSION);

	printfsocket("Done.\n");

#ifdef DEBUG_SOCKET
	closeDebugSocket();
#endif

	return result;
}
