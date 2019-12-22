/*
 * The MIT License (MIT)
 *
 * Copyright (C) zhenghaitao
 * Contact mail with ming8ren@163.com
 *
 */

#ifndef function_type_trait_h
#define function_type_trait_h

#include "macro.h"

namespace function {

struct function_ptr_tag {};
struct function_obj_tag {};

template<typename SIGNATURE> struct type_trait;

#define BUILD_FUNCTION_TRAIT(N) \
template<typename R, typename T ENF_COMM_SPTR_##N ENF_TEPL_DEC_##N> \
struct type_trait<R (T::*)(ENF_TEPL_ARGS_##N)> \
{ \
	typedef R	res_type; \
	typedef T	obj_type; \
	typedef T*	obj_ptr_type; \
	typedef function_obj_tag function_tag; \
}; \
template<typename R ENF_COMM_SPTR_##N ENF_TEPL_DEC_##N> \
struct type_trait<R (*)(ENF_TEPL_ARGS_##N)> \
{ \
	typedef R		res_type; \
	typedef void	obj_type; \
	typedef void*	obj_ptr_type; \
	typedef function_ptr_tag function_tag; \
};

BUILD_FUNCTION_TRAIT(0)
BUILD_FUNCTION_TRAIT(1)
BUILD_FUNCTION_TRAIT(2)
BUILD_FUNCTION_TRAIT(3)
BUILD_FUNCTION_TRAIT(4)
BUILD_FUNCTION_TRAIT(5)
BUILD_FUNCTION_TRAIT(6)
BUILD_FUNCTION_TRAIT(7)
BUILD_FUNCTION_TRAIT(8)
BUILD_FUNCTION_TRAIT(9)

} // namespace function

#endif