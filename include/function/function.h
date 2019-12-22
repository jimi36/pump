/*
 * The MIT License (MIT)
 *
 * Copyright (C) zhenghaitao
 * Contact mail with ming8ren@163.com
 *
 */

#ifndef function_function_h
#define function_function_h

#include "bind.h"
#include "handlers.h"

namespace function {

class function_base
{
public:
	function_base()
	{
		ptr_.obj = 0;
		is_binder_ptr_ = false;
	}

	void reset()
	{
		release();
	}

	void addref()
	{
		binder_base* br = (binder_base*)(ptr_.obj);
		if (br) 
			br->addref();
	}

	void release()
	{
		binder_base* br = (binder_base*)(ptr_.obj);
		if (br) 
			br->release();

		ptr_.obj = 0;
	}

	operator bool()
	{
		if (is_binder_ptr_)
		{
			binder_base* binder = static_cast<binder_base*>(ptr_.obj);
			if (binder)
				return binder->is_valid();
			else
				return false;
		}
		else
		{
			return ptr_.obj != 0;
		}
	}
	
	operator bool() const
	{
		if (is_binder_ptr_)
		{
			binder_base* binder = static_cast<binder_base*>(ptr_.obj);
			if (binder)
				return binder->is_valid();
			else
				return false;
		}
		else
		{
			return ptr_.obj != 0;
		}
	}

protected:
	any_ptr ptr_;
	bool is_binder_ptr_;
};

template<typename SIGNATURE> class function;

template<typename R ENF_COMM_SPTR_0 ENF_TEPL_DEC_0>
class function<R (ENF_TEPL_ARGS_0)>: public function_base
{
protected:
	typedef function self_type;
	typedef R (*HANDLER)(any_ptr ENF_COMM_SPTR_0 ENF_TEPL_ARGS_0);

public:

	function(): handler_(NULL)
	{
	}

	template<typename Functor> function(const Functor &functor)
	{
		ptr_.obj = (void*)(new Functor(functor));
		is_binder_ptr_ = is_binder<Functor>::result;
		handler_ = get_handler0<Functor*, R ENF_COMM_SPTR_0 ENF_TEPL_ARGS_0>::invoke;
	}

	function(const self_type& functor)
	{
		ptr_ = functor.ptr_;
		handler_ = functor.handler_;
		is_binder_ptr_ = functor.is_binder_ptr_;

		addref();
	}

	function(R (*functor)(ENF_TEPL_ARGS_0))
	{
		new (this) function(bind(functor ENF_COMM_SPTR_0 ENF_PLACE_HOLDERS_0));
	}

	~function()
	{
		release();
	}

	R operator ()(ENF_CRPARAM_DEC_0)
	{
		return handler_(ptr_ ENF_COMM_SPTR_0 ENF_ARGS_0);
	}

	function& operator =(const self_type& functor)
	{
		if (this != &functor)
		{
			release();
			new (this) function(functor);
		}
		return *this;
	}

	template<typename Functor> self_type& operator =(const Functor& functor)
	{
		release();
		new (this) function(functor);
		return *this;
	}

private:
	HANDLER handler_;
};

template<typename R ENF_COMM_SPTR_1 ENF_TEPL_DEC_1>
class function<R (ENF_TEPL_ARGS_1)>: public function_base
{
protected:
	typedef function self_type;
	typedef R (*HANDLER)(any_ptr ENF_COMM_SPTR_1 ENF_TEPL_ARGS_1);

public:

	function(): handler_(0)
	{
	}

	template<typename Functor> 
	function(const Functor &functor)
	{
		ptr_.obj = (void*)(new Functor(functor));
		is_binder_ptr_ = is_binder<Functor>::result;
		handler_ = get_handler1<Functor*, R ENF_COMM_SPTR_1 ENF_TEPL_ARGS_1>::invoke;
	}

	function(const self_type& functor)
	{
		ptr_ = functor.ptr_;
		handler_ = functor.handler_;
		is_binder_ptr_ = functor.is_binder_ptr_;

		addref();
	}

	function(R (*functor)(ENF_TEPL_ARGS_1))
	{
		new (this) function(bind(functor ENF_COMM_SPTR_1 ENF_PLACE_HOLDERS_1));
	}

	~function()
	{
		release();
	}

	R operator ()(ENF_CRPARAM_DEC_1)
	{
		return handler_(ptr_ ENF_COMM_SPTR_1 ENF_ARGS_1);
	}

	function& operator =(const self_type& functor)
	{
		if (this != &functor)
		{
			release();
			new (this) function(functor);
		}
		return *this;
	}

	template<typename Functor> self_type& operator =(const Functor& functor)
	{
		release();
		new (this) function(functor);
		return *this;
	}

private:
	HANDLER handler_;
};

template<typename R ENF_COMM_SPTR_2 ENF_TEPL_DEC_2>
class function<R (ENF_TEPL_ARGS_2)>: public function_base
{
protected:
	typedef function self_type;
	typedef R (*HANDLER)(any_ptr ENF_COMM_SPTR_2 ENF_TEPL_ARGS_2);

public:

	function(): handler_(0)
	{
	}

	template<typename Functor> function(const Functor &functor)
	{
		ptr_.obj = (void*)(new Functor(functor));
		is_binder_ptr_ = is_binder<Functor>::result;
		handler_ = get_handler2<Functor*, R ENF_COMM_SPTR_2 ENF_TEPL_ARGS_2>::invoke;
	}

	function(const self_type& functor)
	{
		ptr_ = functor.ptr_;
		handler_ = functor.handler_;
		is_binder_ptr_ = functor.is_binder_ptr_;

		addref();
	}

	function(R (*functor)(ENF_TEPL_ARGS_2))
	{
		new (this) function(bind(functor ENF_COMM_SPTR_2 ENF_PLACE_HOLDERS_2));
	}

	~function()
	{
		release();
	}

	R operator ()(ENF_CRPARAM_DEC_2)
	{
		return handler_(ptr_ ENF_COMM_SPTR_2 ENF_ARGS_2);
	}

	function& operator =(const self_type& functor)
	{
		if (this != &functor)
		{
			release();
			new (this) function(functor);
		}
		return *this;
	}

	template<typename Functor> self_type& operator =(const Functor& functor)
	{
		release();
		new (this) function(functor);
		return *this;
	}

private:
	HANDLER handler_;
};

template<typename R ENF_COMM_SPTR_3 ENF_TEPL_DEC_3>
class function<R (ENF_TEPL_ARGS_3)>: public function_base
{
protected:
	typedef function self_type;
	typedef R (*HANDLER)(any_ptr ENF_COMM_SPTR_3 ENF_TEPL_ARGS_3);

public:

	function(): handler_(0)
	{
	}

	template<typename Functor> function(const Functor &functor)
	{
		ptr_.obj = (void*)(new Functor(functor));
		is_binder_ptr_ = is_binder<Functor>::result;
		handler_ = get_handler3<Functor*, R ENF_COMM_SPTR_3 ENF_TEPL_ARGS_3>::invoke;
	}

	function(const self_type& functor)
	{
		ptr_ = functor.ptr_;
		handler_ = functor.handler_;
		is_binder_ptr_ = functor.is_binder_ptr_;

		addref();
	}

	function(R (*functor)(ENF_TEPL_ARGS_3))
	{
		new (this) function(bind(functor ENF_COMM_SPTR_3 ENF_PLACE_HOLDERS_3));
	}

	~function()
	{
		release();
	}

	R operator ()(ENF_CRPARAM_DEC_3)
	{
		return handler_(ptr_ ENF_COMM_SPTR_3 ENF_ARGS_3);
	}

	function& operator =(const self_type& functor)
	{
		if (this != &functor)
		{
			release();
			new (this) function(functor);
		}
		return *this;
	}

	template<typename Functor> self_type& operator =(const Functor& functor)
	{
		release();
		new (this) function(functor);
		return *this;
	}

private:
	HANDLER handler_;
};

template<typename R ENF_COMM_SPTR_4 ENF_TEPL_DEC_4>
class function<R (ENF_TEPL_ARGS_4)>: public function_base
{
protected:
	typedef function self_type;
	typedef R (*HANDLER)(any_ptr ENF_COMM_SPTR_4 ENF_TEPL_ARGS_4);

public:

	function(): handler_(0)
	{
	}

	template<typename Functor> function(const Functor &functor)
	{
		ptr_.obj = (void*)(new Functor(functor));
		is_binder_ptr_ = is_binder<Functor>::result;
		handler_ = get_handler4<Functor*, R ENF_COMM_SPTR_4 ENF_TEPL_ARGS_4>::invoke;
	}

	function(const self_type& functor)
	{
		ptr_ = functor.ptr_;
		handler_ = functor.handler_;
		is_binder_ptr_ = functor.is_binder_ptr_;

		addref();
	}

	function(R (*functor)(ENF_TEPL_ARGS_4))
	{
		new (this) function(bind(functor ENF_COMM_SPTR_4 ENF_PLACE_HOLDERS_4));
	}

	~function()
	{
		release();
	}

	R operator ()(ENF_CRPARAM_DEC_4)
	{
		return handler_(ptr_ ENF_COMM_SPTR_4 ENF_ARGS_4);
	}

	function& operator =(const self_type& functor)
	{
		if (this != &functor)
		{
			release();
			new (this) function(functor);
		}
		return *this;
	}

	template<typename Functor> self_type& operator =(const Functor& functor)
	{
		release();
		new (this) function(functor);
		return *this;
	}

private:
	HANDLER handler_;
};

template<typename R ENF_COMM_SPTR_5 ENF_TEPL_DEC_5>
class function<R (ENF_TEPL_ARGS_5)>: public function_base
{
protected:
	typedef function self_type;
	typedef R (*HANDLER)(any_ptr ENF_COMM_SPTR_5 ENF_TEPL_ARGS_5);

public:

	function(): handler_(0)
	{
	}

	template<typename Functor> function(const Functor &functor)
	{
		ptr_.obj = (void*)(new Functor(functor));
		is_binder_ptr_ = is_binder<Functor>::result;
		handler_ = get_handler5<Functor*, R ENF_COMM_SPTR_5 ENF_TEPL_ARGS_5>::invoke;
	}

	function(const self_type& functor)
	{
		ptr_ = functor.ptr_;
		handler_ = functor.handler_;
		is_binder_ptr_ = functor.is_binder_ptr_;

		addref();
	}

	function(R (*functor)(ENF_TEPL_ARGS_5))
	{
		new (this) function(bind(functor ENF_COMM_SPTR_5 ENF_PLACE_HOLDERS_5));
	}

	~function()
	{
		release();
	}

	R operator ()(ENF_CRPARAM_DEC_5)
	{
		return handler_(ptr_ ENF_COMM_SPTR_5 ENF_ARGS_5);
	}

	function& operator =(const self_type& functor)
	{
		if (this != &functor)
		{
			release();
			new (this) function(functor);
		}
		return *this;
	}

	template<typename Functor> self_type& operator =(const Functor& functor)
	{
		release();
		new (this) function(functor);
		return *this;
	}

private:
	HANDLER handler_;
};

template<typename R ENF_COMM_SPTR_6 ENF_TEPL_DEC_6>
class function<R (ENF_TEPL_ARGS_6)>: public function_base
{
protected:
	typedef function self_type;
	typedef R (*HANDLER)(any_ptr ENF_COMM_SPTR_6 ENF_TEPL_ARGS_6);

public:

	function(): handler_(0)
	{
	}

	template<typename Functor> function(const Functor &functor)
	{
		ptr_.obj = (void*)(new Functor(functor));
		is_binder_ptr_ = is_binder<Functor>::result;
		handler_ = get_handler6<Functor*, R ENF_COMM_SPTR_6 ENF_TEPL_ARGS_6>::invoke;
	}

	function(const self_type& functor)
	{
		ptr_ = functor.ptr_;
		handler_ = functor.handler_;
		is_binder_ptr_ = functor.is_binder_ptr_;

		addref();
	}

	function(R (*functor)(ENF_TEPL_ARGS_6))
	{
		new (this) function(bind(functor ENF_COMM_SPTR_6 ENF_PLACE_HOLDERS_6));
	}

	~function()
	{
		release();
	}

	R operator ()(ENF_CRPARAM_DEC_6)
	{
		return handler_(ptr_ ENF_COMM_SPTR_6 ENF_ARGS_6);
	}

	function& operator =(const self_type& functor)
	{
		if (this != &functor)
		{
			release();
			new (this) function(functor);
		}
		return *this;
	}

	template<typename Functor> self_type& operator =(const Functor& functor)
	{
		release();
		new (this) function(functor);
		return *this;
	}

private:
	HANDLER handler_;
};

template<typename R ENF_COMM_SPTR_7 ENF_TEPL_DEC_7>
class function<R (ENF_TEPL_ARGS_7)>: public function_base
{
protected:
	typedef function self_type;
	typedef R (*HANDLER)(any_ptr ENF_COMM_SPTR_7 ENF_TEPL_ARGS_7);

public:

	function(): handler_(0)
	{
	}

	template<typename Functor> function(const Functor &functor)
	{
		ptr_.obj = (void*)(new Functor(functor));
		is_binder_ptr_ = is_binder<Functor>::result;
		handler_ = get_handler7<Functor*, R ENF_COMM_SPTR_7 ENF_TEPL_ARGS_7>::invoke;
	}

	function(const self_type& functor)
	{
		ptr_ = functor.ptr_;
		handler_ = functor.handler_;
		is_binder_ptr_ = functor.is_binder_ptr_;

		addref();
	}

	function(R (*functor)(ENF_TEPL_ARGS_7))
	{
		new (this) function(bind(functor ENF_COMM_SPTR_7 ENF_PLACE_HOLDERS_7));
	}

	~function()
	{
		release();
	}

	R operator ()(ENF_CRPARAM_DEC_7)
	{
		return handler_(ptr_ ENF_COMM_SPTR_7 ENF_ARGS_7);
	}

	function& operator =(const self_type& functor)
	{
		if (this != &functor)
		{
			release();
			new (this) function(functor);
		}
		return *this;
	}

	template<typename Functor> self_type& operator =(const Functor& functor)
	{
		release();
		new (this) function(functor);
		return *this;
	}

private:
	HANDLER handler_;
};

template<typename R ENF_COMM_SPTR_8 ENF_TEPL_DEC_8>
class function<R (ENF_TEPL_ARGS_8)>: public function_base
{
protected:
	typedef function self_type;
	typedef R (*HANDLER)(any_ptr ENF_COMM_SPTR_8 ENF_TEPL_ARGS_8);

public:

	function(): handler_(0)
	{
	}

	template<typename Functor> function(const Functor &functor)
	{
		ptr_.obj = (void*)(new Functor(functor));
		is_binder_ptr_ = is_binder<Functor>::result;
		handler_ = get_handler8<Functor*, R ENF_COMM_SPTR_8 ENF_TEPL_ARGS_8>::invoke;
	}

	function(const self_type& functor)
	{
		ptr_ = functor.ptr_;
		handler_ = functor.handler_;
		is_binder_ptr_ = functor.is_binder_ptr_;
	}

	function(R (*functor)(ENF_TEPL_ARGS_8))
	{
		new (this) function(bind(functor ENF_COMM_SPTR_8 ENF_PLACE_HOLDERS_8));
	}

	~function()
	{
		release();
	}

	R operator ()(ENF_CRPARAM_DEC_8)
	{
		return handler_(ptr_ ENF_COMM_SPTR_8 ENF_ARGS_8);
	}

	function& operator =(const self_type& functor)
	{
		if (this != &functor)
		{
			release();
			new (this) function(functor);
		}
		return *this;
	}

	template<typename Functor> self_type& operator =(const Functor& functor)
	{
		release();
		new (this) function(functor);
		return *this;
	}

private:
	HANDLER handler_;
};

template<typename R ENF_COMM_SPTR_9 ENF_TEPL_DEC_9>
class function<R (ENF_TEPL_ARGS_9)>: public function_base
{
protected:
	typedef function self_type;
	typedef R (*HANDLER)(any_ptr ENF_COMM_SPTR_9 ENF_TEPL_ARGS_9);

public:

	function(): handler_(0)
	{
	}

	template<typename Functor> function(const Functor &functor)
	{
		ptr_.obj = (void*)(new Functor(functor));
		is_binder_ptr_ = is_binder<Functor>::result;
		handler_ = get_handler9<Functor*, R ENF_COMM_SPTR_9 ENF_TEPL_ARGS_9>::invoke;
	}

	function(const self_type& functor)
	{
		ptr_ = functor.ptr_;
		handler_ = functor.handler_;
		is_binder_ptr_ = functor.is_binder_ptr_;

		addref();
	}

	function(R (*functor)(ENF_TEPL_ARGS_9))
	{
		new (this) function(bind(functor ENF_COMM_SPTR_9 ENF_PLACE_HOLDERS_9));
	}

	~function()
	{
		release();
	}

	R operator ()(ENF_CRPARAM_DEC_9)
	{
		return handler_(ptr_ ENF_COMM_SPTR_9 ENF_ARGS_9);
	}

	function& operator =(const self_type& functor)
	{
		if (this != &functor)
		{
			release();
			new (this) function(functor);
		}
		return *this;
	}

	template<typename Functor> self_type& operator =(const Functor& functor)
	{
		release();
		new (this) function(functor);
		return *this;
	}

private:
	HANDLER handler_;
};

} // namespace function

#endif
