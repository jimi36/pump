/*
 * The MIT License (MIT)
 *
 * Copyright (C) zhenghaitao
 * Contact mail with ming8ren@163.com
 *
 */

#ifndef function_bindlist_h
#define function_bindlist_h

#include "storage.h"
#include "trackable.h"
#include "type_trait.h"

namespace function {

template<typename F>
class bindlist_base
{
public:
	typedef type_trait<F> trait_type;
	typedef typename trait_type::res_type res_type;
	typedef typename trait_type::obj_type obj_type;
	typedef typename trait_type::obj_ptr_type obj_ptr_type;
	typedef typename trait_type::function_tag function_tag;

public:
	bindlist_base(F f, obj_ptr_type obj): f_(f), obj_(obj) 
	{
		__init_tracker(tf_, obj_);
	}

	bindlist_base(const bindlist_base &bl) 
	{
		new (this) bindlist_base(bl.f_, bl.obj_);
	}

	bool is_valid ()
	{
		if (!tf_.trackable || tf_.tracked_ptr.use_count() != 0)
		{
			return true;
		}
		return false;
	}

private:
	void __init_tracker(track_info &tf, trackable *obj)
	{
		tf.trackable = true;
		tf.tracked_ptr = obj->get_shared_ptr();
	}

	void __init_tracker(track_info &tf, void *obj)
	{
		tf.trackable = false;
	}

protected:
	F f_;
	obj_ptr_type obj_;

	track_info tf_;
};

#define ASSIGN_BINDLIST_BASETYPE \
	typedef bindlist_base<F> base; \
	typedef typename base::res_type res_type; \
	typedef typename base::obj_ptr_type obj_ptr_type; \
	typedef typename base::function_tag function_tag;

#define BUILD_BINDLIST_OPERATOR(N) \
	template <typename CL> res_type operator ()(CL &cl) \
{ \
	return __run(cl, function_tag()); \
} \
	\
	private: \
	template <typename CL> \
	res_type __run(CL &cl, function_ptr_tag) \
{ \
	return (*(this->f_))(ENF_INPUT_ARGS_##N(cl)); \
} \
	\
	template <typename CL> \
	res_type __run(CL &cl, function_obj_tag) \
{ \
	return ((this->obj_)->*(this->f_))(ENF_INPUT_ARGS_##N(cl)); \
}

template<typename F>
class bindlist0 : public bindlist_base<F>, public en_storage0
{
public:
	ASSIGN_BINDLIST_BASETYPE

public:
	bindlist0(F f, obj_ptr_type obj): 
		bindlist_base<F>(f, obj) {}
	
	BUILD_BINDLIST_OPERATOR(0)
};

template<typename F, ENF_TEPL_DEC_1>
class bindlist1 : public bindlist_base<F>, public en_storage1<ENF_TEPL_ARGS_1>
{
public:
	ASSIGN_BINDLIST_BASETYPE

public:
	bindlist1(F f, obj_ptr_type obj, ENF_CRPARAM_DEC_1): 
		bindlist_base<F>(f, obj), en_storage1<ENF_TEPL_ARGS_1>(ENF_ARGS_1){}

	BUILD_BINDLIST_OPERATOR(1)
};

template<typename F, ENF_TEPL_DEC_2>
class bindlist2 : public bindlist_base<F>,  en_storage2<ENF_TEPL_ARGS_2>
{
public:
	ASSIGN_BINDLIST_BASETYPE

public:
	bindlist2(F f, obj_ptr_type obj, ENF_CRPARAM_DEC_2): 
		bindlist_base<F>(f, obj), en_storage2<ENF_TEPL_ARGS_2>(ENF_ARGS_2){}

	BUILD_BINDLIST_OPERATOR(2)
};

template<typename F, ENF_TEPL_DEC_3>
class bindlist3 : public bindlist_base<F>, public en_storage3<ENF_TEPL_ARGS_3>
{
public:
	ASSIGN_BINDLIST_BASETYPE

public:
	bindlist3(F f, obj_ptr_type obj, ENF_CRPARAM_DEC_3): 
		bindlist_base<F>(f, obj), en_storage3<ENF_TEPL_ARGS_3>(ENF_ARGS_3) {}

	BUILD_BINDLIST_OPERATOR(3)
};

template<typename F, ENF_TEPL_DEC_4>
class bindlist4 : public bindlist_base<F>, public en_storage4<ENF_TEPL_ARGS_4>
{
public:
	ASSIGN_BINDLIST_BASETYPE

public:
	bindlist4(F f, obj_ptr_type obj, ENF_CRPARAM_DEC_4): 
		bindlist_base<F>(f, obj), en_storage4<ENF_TEPL_ARGS_4>(ENF_ARGS_4) {}

	BUILD_BINDLIST_OPERATOR(4)
};

template<typename F, ENF_TEPL_DEC_5>
class bindlist5 : public bindlist_base<F>, public en_storage5<ENF_TEPL_ARGS_5>
{
public:
	ASSIGN_BINDLIST_BASETYPE

public:
	bindlist5(F f, obj_ptr_type obj, ENF_CRPARAM_DEC_5): 
		bindlist_base<F>(f, obj), en_storage5<ENF_TEPL_ARGS_5>(ENF_ARGS_5) {}

	BUILD_BINDLIST_OPERATOR(5)
};

template<typename F, ENF_TEPL_DEC_6>
class bindlist6 : public bindlist_base<F>, public en_storage6<ENF_TEPL_ARGS_6>
{
public:
	ASSIGN_BINDLIST_BASETYPE

public:
	bindlist6(F f, obj_ptr_type obj, ENF_CRPARAM_DEC_6): 
		bindlist_base<F>(f, obj), en_storage6<ENF_TEPL_ARGS_6>(ENF_ARGS_6) {}

	BUILD_BINDLIST_OPERATOR(6)
};

template<typename F, ENF_TEPL_DEC_7>
class bindlist7 : public bindlist_base<F>, public en_storage7<ENF_TEPL_ARGS_7>
{
public:
	ASSIGN_BINDLIST_BASETYPE

public:
	bindlist7(F f, obj_ptr_type obj, ENF_CRPARAM_DEC_7): 
		bindlist_base<F>(f, obj), en_storage7<ENF_TEPL_ARGS_7>(ENF_ARGS_7) {}

	BUILD_BINDLIST_OPERATOR(7)
};

template<typename F, ENF_TEPL_DEC_8>
class bindlist8 : public bindlist_base<F>, public en_storage8<ENF_TEPL_ARGS_8>
{
public:
	ASSIGN_BINDLIST_BASETYPE

public:
	bindlist8(F f, obj_ptr_type obj, ENF_CRPARAM_DEC_8): 
		bindlist_base<F>(f, obj), en_storage8<ENF_TEPL_ARGS_8>(ENF_ARGS_8) {}

	BUILD_BINDLIST_OPERATOR(8)
};

template<typename F, ENF_TEPL_DEC_9>
class bindlist9 : public bindlist_base<F>, public en_storage9<ENF_TEPL_ARGS_9>
{
public:
	ASSIGN_BINDLIST_BASETYPE

public:
	bindlist9(F f, obj_ptr_type obj, ENF_CRPARAM_DEC_9): 
		bindlist_base<F>(f, obj), en_storage9<ENF_TEPL_ARGS_9>(ENF_ARGS_9) {}

	BUILD_BINDLIST_OPERATOR(9)
};

} // namespace function

#endif
