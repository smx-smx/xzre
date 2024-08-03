/**
 * Copyright (C) 2024 Stefano Moioli <smxdev4@gmail.com>
 **/
#include "xzre.h"

BOOL find_function(
	u8 *code_start,
	void **func_start,
	void **func_end,
	u8 *search_base,
	u8 *code_end,
	FuncFindType find_mode
){
	u8 *res = NULL;
	/** should we locate the function prologue? */
	if(func_start){
		for(u8 *p = code_start;
			search_base < p && !find_function_prologue(p, code_end, &res, find_mode);
			--p);

		if(!res || res == search_base && !find_function_prologue(search_base, code_end, NULL, find_mode)){
			return FALSE;
		}
		*func_start = res;
	}
	/** should we locate the function epilogue? */
	if(func_end){
		u8 *search_from = code_start + 1;
		u8 *search_to = code_end - 4;
		BOOL found;
		for(;search_from < search_to && 
			(found=find_function_prologue(search_from, code_end, NULL, find_mode)) == FALSE;
			++search_from
		);
		// FIXME: in theory the first check is redundant, as it's covered by the second one
		if(found || search_to != search_from || find_function_prologue(search_from, code_end, NULL, find_mode)){
			code_end = search_from;
		}
		*func_end = code_end;
	}
	return TRUE;
}