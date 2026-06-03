// adapted from https://github.com/PSP-Archive/ARK-4/blob/main/loader/live/kernel/psxloader/ps1cfw_enabler/ps1cfw_enabler.c

#include <taihen.h>
#include <vitasdk.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "Log.h"

#define SCE_PSPEMU_CACHE_NONE 0x1

typedef struct PopsConfig{
    uint32_t magic;
    char title_id[20];
    char path[256];
}PopsConfig;

#define ARK_MAGIC 0xB00B1E55


static SceUID io_patch_path = -1;
static SceUID io_patch_size = -1;
static SceUID ctrl_patch = -1;

static const uint32_t movs_a1_0_nop_opcode = 0xBF002000;
static const uint32_t nop_nop_opcode = 0xBF00BF00;
static const uint32_t mov_r2_r4_mov_r4_r2 = 0x46224614;
static const uint32_t mips_move_a2_0 = 0x00003021;
static const uint32_t mips_nop = 0;

static PopsConfig popsconfig;

static void * psp_sysmem_patch_addr = NULL;
static int (* ScePspemuErrorExit)(int error);
static int (* ScePspemuConvertAddress)(uint32_t addr, int mode, uint32_t cache_size);
static int (* ScePspemuWritebackCache)(void *addr, int size);
static int (* ScePspemuPausePops)(int pause);


static void get_functions(tai_module_info_t tai_info, uint32_t text_addr) {
    ScePspemuErrorExit                  = (void *)(text_addr + 0x4104 + 0x1);
    ScePspemuConvertAddress             = (void *)(text_addr + 0x6364 + 0x1);
    ScePspemuWritebackCache             = (void *)(text_addr + 0x6490 + 0x1);
  
    if (tai_info.module_nid == 0x2714F07D) {
		psp_sysmem_patch_addr           = (void *)0x88010044;
        ScePspemuPausePops              = (void *)(text_addr + 0x300C0 + 0x1);
    }
    else {
		psp_sysmem_patch_addr           = (void *)0x8800FFB4;
        ScePspemuPausePops              = (void *)(text_addr + 0x300D4 + 0x1);
    }
}

// IO Open patched
int sceIoOpenPS1(char* file) {
  
    // Virtual Kernel Exploit (allow easy escalation of priviledge on ePSP)
    if (strstr(file, "__dokxploit__") != 0){
        uint32_t *m;
        
        // remove k1 checks in IoRead (lets you write into kram)
        m = (uint32_t *)ScePspemuConvertAddress(0x8805769C, SCE_PSPEMU_CACHE_NONE, 4);
        *m = mips_move_a2_0; // move $a2, 0
        ScePspemuWritebackCache(m, 4);

        // remove k1 checks in IoWrite (lets you read kram)
        m = (uint32_t *)ScePspemuConvertAddress(0x880577B0, SCE_PSPEMU_CACHE_NONE, 4);
        *m = mips_move_a2_0; // move $a2, 0
        ScePspemuWritebackCache(m, 4);

        // allow running any code as kernel (lets us pass function pointer as second argument of libctime)
        //m = (uint32_t *)ScePspemuConvertAddress((tai_info.module_nid==0x2714F07D)?0x88010044:0x8800FFB4, SCE_PSPEMU_CACHE_NONE, 4);
		m = (uint32_t *)ScePspemuConvertAddress(psp_sysmem_patch_addr, SCE_PSPEMU_CACHE_NONE, 4);
        *m = mips_nop; // nop
        ScePspemuWritebackCache(m, 4);

        return 0;
    }

    // Configure currently loaded game
    char* popsetup = strstr(file, "__popsconfig__");
    if (popsetup){
        char* title_id = strchr(popsetup, '/') + 1;
        char* path = strchr(title_id, '/');
        strncpy(popsconfig.title_id, title_id, (path-title_id));
        strcpy(popsconfig.path, path);
        popsconfig.magic = ARK_MAGIC;
        return 0;
    }

    // Clear configuration 
    if (strstr(file, "__popsclear__")){
        memset(&popsconfig, 0, sizeof(PopsConfig));
        return 0;
    }
    
    // Handle when system has booted
    if (strstr(file, "__popsbooted__")){
        sceShellUtilUnlock(SCE_SHELL_UTIL_LOCK_TYPE_PS_BTN);
        sceShellUtilUnlock(SCE_SHELL_UTIL_LOCK_TYPE_PS_BTN_2);
        sceKernelPowerUnlock(0);
        return 0;
    }
    
    // Pause POPS
    if (strstr(file, "__popspause__")){
        ScePspemuPausePops(1);
        sceDisplayWaitVblankStart();
        return 0;
    }
    
    // Resume POPS
    if (strstr(file, "__popsresume__")){
        ScePspemuPausePops(0);
        sceDisplayWaitVblankStart();
        return 0;
    }
    
    // Clean Exit
    if (strstr(file, "__popsexit__")){
        return ScePspemuErrorExit(0);
    }

    // Redirect files for memory card manager
    if (popsconfig.magic == ARK_MAGIC && popsconfig.title_id[0] && popsconfig.path[0]){
      char *p = strrchr(file, '/');
      if (p) {
        char new_file[256];
        if (strcmp(p+1, "__sce_menuinfo") == 0) {
          char *filename = popsconfig.path;
          char *q = strrchr(filename, '/');
          if (q) {
            char path[128];
            strncpy(path, filename, q-(filename));
            path[q-filename] = '\0';

            snprintf(new_file, sizeof(new_file), "ms0:%s/__sce_menuinfo", path);
            strcpy(file, new_file);
          }
        } else if (strstr(file, "/SCPS10084/") &&
                  (strcmp(p+1, "PARAM.SFO") == 0 ||
                   strcmp(p+1, "SCEVMC0.VMP") == 0 ||
                   strcmp(p+1, "SCEVMC1.VMP") == 0)) {
          snprintf(new_file, sizeof(new_file), "ms0:PSP/SAVEDATA/%s/%s", popsconfig.title_id, p+1);
          strcpy(file, new_file);
        }
      }
    }
    return -1;
}

int sceIoGetstatPS1(char *file) {
  if (popsconfig.magic == ARK_MAGIC && popsconfig.title_id[0] && popsconfig.path[0]){
      char *p = strrchr(file, '/');
      if (p) {
        char new_file[256];
        if (strstr(file, "/SCPS10084/") &&
           (strcmp(p+1, "PARAM.SFO") == 0 ||
            strcmp(p+1, "SCEVMC0.VMP") == 0 ||
            strcmp(p+1, "SCEVMC1.VMP") == 0)) {
          snprintf(new_file, sizeof(new_file), "ms0:PSP/SAVEDATA/%s/%s", popsconfig.title_id, p+1);
          strcpy(file, new_file);
          return 0;
        }
      }
  }
  return -1;
}

int ps1cfw_enabler_start(tai_module_info_t tai_info) {
    memset(&popsconfig, 0, sizeof(PopsConfig));

	SceKernelModuleInfo mod_info;
	mod_info.size = sizeof(SceKernelModuleInfo);
	sceKernelGetModuleInfo(tai_info.modid, &mod_info);

    // Get PspEmu functions
    get_functions(tai_info, (uint32_t)mod_info.segments[0].vaddr);

    // allow opening any path
    io_patch_path = taiInjectData(tai_info.modid, 0x00, 0x839C, &nop_nop_opcode, 0x4);

    // allow opening files of any size
    io_patch_size = taiInjectData(tai_info.modid, 0x00, 0xA13C, &mov_r2_r4_mov_r4_r2, 0x4);

    // fix controller on Vita TV
    ctrl_patch = taiInjectData(tai_info.modid, 0, (tai_info.module_nid == 0x2714F07D)?0x2073C:0x20740, &movs_a1_0_nop_opcode, sizeof(movs_a1_0_nop_opcode));

    return SCE_KERNEL_START_SUCCESS;
}

int ps1cfw_enabler_stop() {

	if (io_patch_path >= 0) taiInjectRelease(io_patch_path);
	if (io_patch_size >= 0) taiInjectRelease(io_patch_size);
	if (ctrl_patch    >= 0) taiInjectRelease(ctrl_patch);

	return SCE_KERNEL_STOP_SUCCESS;
}
