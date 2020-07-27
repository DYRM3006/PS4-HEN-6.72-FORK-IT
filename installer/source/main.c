#include "ps4.h"

#include "defines.h"
#include "debug.h"
#include "offsets.h"

#define PS4_UPDATE_FULL_PATH "/update/PS4UPDATE.PUP"
#define PS4_UPDATE_TEMP_PATH "/update/PS4UPDATE.PUP.net.temp"



extern char kpayload[];
unsigned kpayload_size;

int install_payload(struct thread *td, struct install_payload_args* args)
{
	//debugPrint("staring kpayload");
	struct ucred* cred;
	struct filedesc* fd;

	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;

	uint8_t* kernel_base = (uint8_t*)(__readmsr(0xC0000082) - XFAST_SYSCALL_addr);
	uint8_t* kernel_ptr = (uint8_t*)kernel_base;
	void** got_prison0 = (void**)&kernel_ptr[PRISON0_addr];
	void** got_rootvnode = (void**)&kernel_ptr[ROOTVNODE_addr];

	void (*pmap_protect)(void * pmap, uint64_t sva, uint64_t eva, uint8_t pr) = (void *)(kernel_base + pmap_protect_addr);
	void *kernel_pmap_store = (void *)(kernel_base + PMAP_STORE_addr);

	uint8_t* payload_data = args->payload_info->buffer;
	size_t payload_size = args->payload_info->size;
	struct payload_header* payload_header = (struct payload_header*)payload_data;
	uint8_t* payload_buffer = (uint8_t*)&kernel_base[DT_HASH_SEGMENT_addr];

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
	//*(uint32_t *)(kernel_base + debug_menu_error_patch1) = 0;
	//*(uint32_t *)(kernel_base + debug_menu_error_patch2) = 0;
	
	//-- thanks to OpenOrbis bois for this patches!
	uint8_t *kmem;
	// Disable pfs checks
	kmem = (uint8_t*)&kernel_base[0x6A8EB0];
	kmem[0] = 0x31; 
	kmem[1] = 0xC0; 
	kmem[2] = 0xC3; 
	kmem[3] = 0x90;

	kmem = (uint8_t*)&kernel_base[0x003C1857];
	kmem[0] = 0x41;
	kmem[1] = 0x41;
	//debugPrint("pfs patched");

	// flatz enable debug RIFs 5.05
	kmem = (uint8_t*)&kernel_base[0x66AEB0];
	kmem[0] = 0xB0; 
	kmem[1] = 0x01; 
	kmem[2] = 0xC3; 
	kmem[3] = 0x90;
	//debugPrint("rifs patched");

	// Patch dynlib_dlsym
	kmem = (uint8_t*)&kernel_base[0x1D895A];
	kmem[0] = 0x90;
	kmem[1] = 0x90;
	kmem[2] = 0x90;
	kmem[3] = 0x90;
	kmem[4] = 0x90;
	kmem[5] = 0x90;
	//debugPrint("dlsym patched");

	// enable debug log
	//*(uint16_t*)(kernel_base + enable_debug_log_patch) = 0x38EB;

	// enable uart output
	//*(uint32_t *)(kernel_base + enable_uart_patch) = 0;

	// install kpayload
	/*debugPrint("installing payload");
	memset(payload_buffer, 0, PAGE_SIZE);
	memcpy(payload_buffer, payload_data, payload_size);
	debugPrint("done");

	uint64_t sss = ((uint64_t)payload_buffer) & ~(uint64_t)(PAGE_SIZE-1);
	uint64_t eee = ((uint64_t)payload_buffer + payload_size + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE-1);
	kernel_base[pmap_protect_p_addr] = 0xEB;
	pmap_protect(kernel_pmap_store, sss, eee, 7);
	kernel_base[pmap_protect_p_addr] = 0x75;
	debugPrint("done2")*/;

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
	initNetwork();
	initPthread();

	int debugSock;	

	#define debugPrint(format, ...)\
		do {\
			char buffer[512];\
			int size = sprintf(buffer, format, ##__VA_ARGS__);\
			sceNetSend(debugSock, buffer, size, 0);\
		} while(0)\

	void enableDebug() {
		char debugSocketName[] = "debug";
		struct sockaddr_in debugServer;
		debugServer.sin_len = sizeof(debugServer);
		debugServer.sin_family = AF_INET;
		debugServer.sin_addr.s_addr = IP(192, 168, 2, 71);
		debugServer.sin_port = sceNetHtons(9024);
		memset(debugServer.sin_zero, 0, sizeof(debugServer.sin_zero));
		debugSock = sceNetSocket(debugSocketName, AF_INET, SOCK_STREAM, 0);
		sceNetConnect(debugSock, (struct sockaddr *)&debugServer, sizeof(debugServer));
	}

	void disableDebug() {
		sceNetSocketClose(debugSock);
	}

	enableDebug();
	debugPrint("Starting payload...\n");

	struct payload_info payload_info;
	payload_info.buffer = (uint8_t *)kpayload;
	payload_info.size = (size_t)kpayload_size;

	errno = 0;

	result = kexec(&install_payload, &payload_info);
	result = !result ? 0 : errno;
	debugPrint("install_payload: %d\n", result);

	patch_update();

	initSysUtil();
	notify("Welcome to PS4HEN v"VERSION);

	debugPrint("Done.\n");
	disableDebug();

	return result;
}
