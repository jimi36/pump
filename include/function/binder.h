/*
 * The MIT License (MIT)
 *
 * Copyright (C) zhenghaitao
 * Contact mail with ming8ren@163.com
 *
 */

#ifndef function_binder_h
#define function_binder_h

#include <atomic> 
#include "calllist.h"
#include "bindlist.h"

namespace function {

class binder_base
{
public:
	binder_base(): ref_(1)
	{
	}

	virtual ~binder_base()
	{
	}

	void addref()
	{
		ref_.fetch_add(1);
	}

	void release()
	{
		if (ref_.fetch_sub(1) == 1)
		{
			delete this;
		}
	}
	
	operator bool()
	{
		return is_valid();
	}

	virtual bool is_valid() = 0;

private:
	std::atomic_int ref_;
};

template<typename BL>
class binder: public binder_base
{
public:
	typedef typename BL::res_type res_type;

public:
	binder(BL & bl): bl_(bl)
	{
	}

	binder(BL && bl): bl_(bl)
	{
	}

	binder(const binder & r): bl_(r.bl_)
	{
	}

	virtual ~binder()
	{
	}

	virtual bool is_valid() { return bl_.is_valid(); }

public:
	res_type operator ()()
	{
		calllist0 cl;
		return bl_(cl); 
	}

	template<ENF_TEPL_DEC_1>
	res_type operator ()(ENF_CRPARAM_DEC_NC_1)
	{ 
		calllist1<ENF_TEPL_ARGS_QU_1> cl(ENF_ARGS_1);
		return bl_(cl); 
	}

	template<ENF_TEPL_DEC_2>
	res_type operator ()(ENF_CRPARAM_DEC_NC_2)
	{ 
		calllist2<ENF_TEPL_ARGS_QU_2> cl(ENF_ARGS_2);
		return bl_(cl); 
	}

	template<ENF_TEPL_DEC_3>
	res_type operator ()(ENF_CRPARAM_DEC_NC_3)
	{
		calllist3<ENF_TEPL_ARGS_QU_3> cl(ENF_ARGS_3);
		return bl_(cl); 
	}

	template<ENF_TEPL_DEC_4>
	res_type operator ()(ENF_CRPARAM_DEC_NC_4)
	{
		calllist4<ENF_TEPL_ARGS_QU_4> cl(ENF_ARGS_4);
		return bl_(cl); 
	}

	template<ENF_TEPL_DEC_5>
	res_type operator ()(ENF_CRPARAM_DEC_NC_5)
	{
		calllist5<ENF_TEPL_ARGS_QU_5> cl(ENF_ARGS_5);
		return bl_(cl); 
	}

	template<ENF_TEPL_DEC_6>
	res_type operator ()(ENF_CRPARAM_DEC_NC_6)
	{
		calllist6<ENF_TEPL_ARGS_QU_6> cl(ENF_ARGS_6);
		return bl_(cl); 
	}

	template<ENF_TEPL_DEC_7>
	res_type operator ()(ENF_CRPARAM_DEC_NC_7)
	{
		calllist7<ENF_TEPL_ARGS_QU_7> cl(ENF_ARGS_7);
		return bl_(cl); 
	}

	template<ENF_TEPL_DEC_8>
	res_type operator ()(ENF_CRPARAM_DEC_NC_8)
	{
		calllist8<ENF_TEPL_ARGS_QU_8> cl(ENF_ARGS_8);
		return bl_(cl); 
	}

	template<ENF_TEPL_DEC_9>
	res_type operator ()(ENF_CRPARAM_DEC_NC_9)
	{
		calllist9<ENF_TEPL_ARGS_QU_9> cl(ENF_ARGS_9);
		return bl_(cl); 
	}

private:
	BL bl_;
};

template<typename T>
struct is_binder {
	static char  __test(binder_base*);
	static short __test(...);
	const static bool result = sizeof(__test((T*)0)) == sizeof(char);
};

} // namespace function

#endif