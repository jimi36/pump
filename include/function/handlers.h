/*
 * The MIT License (MIT)
 *
 * Copyright (C) zhenghaitao
 * Contact mail with ming8ren@163.com
 *
 */

#ifndef function_handler_h
#define function_handler_h

#include "macro.h"

namespace function {

typedef void* any_ptr;

template <typename Functor>
struct get_functor_destroyer
{
	static void invoke(any_ptr ptr)
	{
		if (ptr)
		{
			Functor *tmp = reinterpret_cast<Functor*>(ptr);
			delete tmp;
		}
	}
};

template<typename F, typename R ENF_COMM_SPTR_0 ENF_TEPL_DEC_0>
struct get_handler0
{
	static R invoke(any_ptr ptr ENF_COMM_SPTR_0 ENF_PARAM_DEC_0)
	{
		F f = reinterpret_cast<F>(ptr);
		return (*f)(ENF_ARGS_0);
	}
};

template<typename F, typename R ENF_COMM_SPTR_1 ENF_TEPL_DEC_1>
struct get_handler1
{
	static R invoke(any_ptr ptr ENF_COMM_SPTR_1 ENF_PARAM_DEC_1)
	{
		F f = reinterpret_cast<F>(ptr);
		return (*f)(ENF_ARGS_1);
	}
};

template<typename F, typename R ENF_COMM_SPTR_2 ENF_TEPL_DEC_2>
struct get_handler2
{
	static R invoke(any_ptr ptr ENF_COMM_SPTR_2 ENF_PARAM_DEC_2)
	{
		F f = reinterpret_cast<F>(ptr);
		return (*f)(ENF_ARGS_2);
	}
};

template<typename F, typename R ENF_COMM_SPTR_3 ENF_TEPL_DEC_3>
struct get_handler3
{
	static R invoke(any_ptr ptr ENF_COMM_SPTR_3 ENF_PARAM_DEC_3)
	{
		F f = reinterpret_cast<F>(ptr);
		return (*f)(ENF_ARGS_3);
	}
};

template<typename F, typename R ENF_COMM_SPTR_4 ENF_TEPL_DEC_4>
struct get_handler4
{
	static R invoke(any_ptr ptr ENF_COMM_SPTR_4 ENF_PARAM_DEC_4)
	{
		F f = reinterpret_cast<F>(ptr);
		return (*f)(ENF_ARGS_4);
	}
};

template<typename F, typename R ENF_COMM_SPTR_5 ENF_TEPL_DEC_5>
struct get_handler5
{
	static R invoke(any_ptr ptr ENF_COMM_SPTR_5 ENF_PARAM_DEC_5)
	{
		F f = reinterpret_cast<F>(ptr);
		return (*f)(ENF_ARGS_5);
	}
};

template<typename F, typename R ENF_COMM_SPTR_6 ENF_TEPL_DEC_6>
struct get_handler6
{
	static R invoke(any_ptr ptr ENF_COMM_SPTR_6 ENF_PARAM_DEC_6)
	{
		F f = reinterpret_cast<F>(ptr);
		return (*f)(ENF_ARGS_6);
	}
};

template<typename F, typename R ENF_COMM_SPTR_7 ENF_TEPL_DEC_7>
struct get_handler7
{
	static R invoke(any_ptr ptr ENF_COMM_SPTR_7 ENF_PARAM_DEC_7)
	{
		F f = reinterpret_cast<F>(ptr);
		return (*f)(ENF_ARGS_7);
	}
};

template<typename F, typename R ENF_COMM_SPTR_8 ENF_TEPL_DEC_8>
struct get_handler8
{
	static R invoke(any_ptr ptr ENF_COMM_SPTR_8 ENF_PARAM_DEC_8)
	{
		F f = reinterpret_cast<F>(ptr);
		return (*f)(ENF_ARGS_8);
	}
};

template<typename F, typename R ENF_COMM_SPTR_9 ENF_TEPL_DEC_9>
struct get_handler9
{
	static R invoke(any_ptr ptr ENF_COMM_SPTR_9 ENF_PARAM_DEC_9)
	{
		F f = reinterpret_cast<F>(ptr);
		return (*f)(ENF_ARGS_9);
	}
};

} // namespace function

#endif