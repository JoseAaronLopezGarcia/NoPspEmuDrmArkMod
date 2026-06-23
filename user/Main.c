#include <vitasdk.h>

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <taihen.h>

#include "PspEmu.h"
#include "SceShell.h"
#include "Log.h"
#include "ps1cfw_enabler.h"

static int patched_pspemu = 0;
static int patched_sceshell = 0;

void _start() __attribute__ ((weak, alias ("module_start"))); 
int module_start(SceSize args, void *argp) {
	
	tai_module_info_t tai_info;
	tai_info.size = sizeof(tai_module_info_t);

	if (taiGetModuleInfo("AdrenalineUser", &tai_info) >= 0){
	    return SCE_KERNEL_START_SUCCESS;
	}
	
	SceUID ret = taiGetModuleInfo("ScePspemu", &tai_info);
	if (ret >= 0){
		patched_pspemu = 1;
		pspemu_module_start(tai_info);
		ps1cfw_enabler_start(tai_info);
		rightanalog_start();
		return SCE_KERNEL_START_SUCCESS;
	}
	
	ret = taiGetModuleInfo("SceShell", &tai_info);
	if (ret >= 0){
		patched_sceshell = 1;
		sceshell_module_start(tai_info);
		return SCE_KERNEL_START_SUCCESS;
	}

	return SCE_KERNEL_START_NO_RESIDENT;
}

int module_stop(SceSize args, void *argp) {
	if (patched_pspemu) {
		ps1cfw_enabler_stop();
		pspemu_module_stop();
		rightanalog_stop();
		return SCE_KERNEL_STOP_SUCCESS;
	}
	if (patched_sceshell){
		sceshell_module_stop();
		return SCE_KERNEL_STOP_SUCCESS;
	}
	return SCE_KERNEL_STOP_SUCCESS;
}
