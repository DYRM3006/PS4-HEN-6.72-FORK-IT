#ifndef __OFFSETS_H__
#define __OFFSETS_H__
#pragma once

// data - tested
#define	XFAST_SYSCALL_addr              0x000001C0
#define M_TEMP_addr                     0x01540EB0
#define MINI_SYSCORE_SELF_BINARY_addr   0x0156A588
#define ALLPROC_addr                    0x022BBE80
#define SBL_DRIVER_MAPPED_PAGES_addr    0x0266AC68
#define SBL_PFS_SX_addr                 0x02679040
#define SBL_KEYMGR_KEY_SLOTS_addr       0x02694570
#define SBL_KEYMGR_KEY_RBTREE_addr      0x02694580
#define SBL_KEYMGR_BUF_VA_addr          0x02698000
#define SBL_KEYMGR_BUF_GVA_addr         0x02698808
#define FPU_CTX_addr                    0x02694080
//#define DIPSW_addr                      0x1CD0650

// common - tested
#define memcmp_addr                     0x00207E40
#define _sx_xlock_addr                  0x000426C0
#define _sx_xunlock_addr                0x00042880
#define malloc_addr                     0x0000D7A0
#define free_addr                       0x0000D9A0
#define strstr_addr                     0x004817F0
#define fpu_kern_enter_addr             0x0036B6E0
#define fpu_kern_leave_addr             0x0036B7D0
#define memcpy_addr                     0x003C15B0
#define memset_addr                     0x001687D0
#define strlen_addr                     0x002433E0
#define printf_addr                     0x00123280
#define eventhandler_register_addr      0x00402E80

// Fself - tested
#define sceSblACMgrGetPathId_addr       0x00233C70
#define sceSblServiceMailbox_addr       0x0064CC20
#define sceSblAuthMgrSmIsLoadable2_addr 0x0065D7A0
#define _sceSblAuthMgrGetSelfInfo_addr  0x0065E010
#define _sceSblAuthMgrSmStart_addr      0x0065E490
#define sceSblAuthMgrVerifyHeader_addr  0x0065D800

// Fpkg - tested
#define RsaesPkcs1v15Dec2048CRT_addr    0x001D6050
#define Sha256Hmac_addr                 0x00335B70
#define AesCbcCfb128Encrypt_addr        0x003C0320
#define AesCbcCfb128Decrypt_addr        0x003C0550
#define sceSblDriverSendMsg_0_addr      0x00637AE0
#define sceSblPfsSetKeys_addr           0x00641520
#define sceSblKeymgrSetKeyStorage_addr  0x00646E00
#define sceSblKeymgrSetKeyForPfs_addr   0x00649800
#define sceSblKeymgrCleartKey_addr      0x00649B80
#define sceSblKeymgrSmCallfunc_addr     0x006493D0

// Patch - tested
#define vmspace_acquire_ref_addr        0x0044CB90
#define vmspace_free_addr               0x0044C9C0
#define vm_map_lock_read_addr           0x0044CD40
#define vm_map_unlock_read_addr         0x0044CD90
#define vm_map_lookup_entry_addr        0x0044D330 		//HAVE TO SEARCH 
#define proc_rwmem_addr                 0x0010EE10

// Fself hooks - tested
#define sceSblAuthMgrIsLoadable__sceSblACMgrGetPathId_hook          0x006591BC
#define sceSblAuthMgrIsLoadable2_hook                               0x0065930F
#define sceSblAuthMgrVerifyHeader_hook1                             0x00659AC6
#define sceSblAuthMgrVerifyHeader_hook2                             0x0065A758
#define sceSblAuthMgrSmLoadSelfSegment__sceSblServiceMailbox_hook   0x0066092A
#define sceSblAuthMgrSmLoadSelfBlock__sceSblServiceMailbox_hook     0x00661571

// Fpkg hooks - tested
#define sceSblKeymgrSetKeyStorage__sceSblDriverSendMsg_hook         0x00646EA5
#define sceSblKeymgrInvalidateKey__sx_xlock_hook                    0x0064AA3D
#define sceSblKeymgrSmCallfunc_npdrm_decrypt_isolated_rif_hook      0x00669500
#define sceSblKeymgrSmCallfunc_npdrm_decrypt_rif_new_hook           0x0066A313
#define mountpfs__sceSblPfsSetKeys_hook1                            0x006CDF15
#define mountpfs__sceSblPfsSetKeys_hook2                            0x006CE141

// SceShellUI patches - debug patches
//#define sceSblRcMgrIsAllowDebugMenuForSettings_patch                0x01BD90
//#define sceSblRcMgrIsStoreMode_patch                                0x01C090

// SceShellUI patches - remote play patches
//#define CreateUserForIDU_patch                                      0x1A8FA0
//#define remote_play_menu_patch                                      0xEE638E

// SceRemotePlay patches - remote play patches
//#define SceRemotePlay_patch1                                        0x03C33F
//#define SceRemotePlay_patch2                                        0x03C35A

// SceShellCore patches
#define sceKernelIsGenuineCEX_patch1    0x00189602
#define sceKernelIsGenuineCEX_patch2    0x00835642
#define sceKernelIsGenuineCEX_patch3    0x00880492
#define sceKernelIsGenuineCEX_patch4    0x00A12B92

// call nidf_libSceDipsw
#define nidf_libSceDipsw_patch1         0x00189630
#define nidf_libSceDipsw_patch2         0x00254107
#define nidf_libSceDipsw_patch3         0x00835670
#define nidf_libSceDipsw_patch4         0x00A12BC0

// enable data mount
#define enable_data_mount_patch         0x001C5E03

// enable fpkg
#define enable_fpkg_patch               0x0048F350

// 'sce_sdmemory' patch
//#define sce_sdmemory_patch				0xD42843
 
//verify keystone patch
#define verify_keystone_patch			0x007E5B6E

//transfer mount permission patch eg mount foreign saves with write permission
#define save_mount_permision			0x0 //0x68BA0

//some other patch not sure 
#define save_mount_patch				0x0 //0x6A349

//something something patch
#define save_mount_something_patch		0x0 //0x686AE

//patch unk 
#define save_mount_patch_unk			0x0 //0x67FCA

//save mount never jump
#define save_mount_never_jump			0x0 //0x67798

//save data always jump
#define save_mount_always_jump			0x0 //0x679D5

//psn save patch 
#define save_psn_patch					0x0 //0xC54F0
 
// debug pkg free string
#define fake_free_patch                 0x00FD2BF1

// make pkgs installer working with external hdd
#define pkg_installer_patch             0x0 //0x9312A1

// enable support with 6.xx external hdd
#define ext_hdd_patch                   0x0 //0x593C7D

// enable debug trophies on retail
#define debug_trophies_patch            0x06CF26C

// disable screenshot block
#define disable_screenshot_patch        0x0 //0x0CB8C6

#endif