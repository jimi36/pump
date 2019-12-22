/*
 * The MIT License (MIT)
 *
 * Copyright (C) zhenghaitao
 * Contact mail with ming8ren@163.com
 *
 */

#ifndef function_bind_h
#define function_bind_h

#include "binder.h"

namespace function {

template<typename R ENF_COMM_SPTR_0 ENF_TEPL_T_DEC_0 ENF_COMM_SPTR_0 ENF_TEPL_DEC_0>
binder<bindlist0<R (*)(ENF_TEPL_T_ARGS_0) ENF_COMM_SPTR_0 ENF_TEPL_ARGS_0> > bind(R (*f)(ENF_TEPL_T_ARGS_0) ENF_COMM_SPTR_0 ENF_CRPARAM_DEC_0)
{
	typedef R (*F)(ENF_TEPL_T_ARGS_0);
	typedef bindlist0<F ENF_COMM_SPTR_0 ENF_TEPL_ARGS_0> bindlist_type;
	//bindlist_type bl(f, 0 ENF_COMM_SPTR_0 ENF_ARGS_0);
	return binder<bindlist_type>(bindlist_type(f, 0 ENF_COMM_SPTR_0 ENF_ARGS_0));
}

template<typename R, typename T ENF_COMM_SPTR_0 ENF_TEPL_T_DEC_0 ENF_COMM_SPTR_0 ENF_TEPL_DEC_0>
binder<bindlist0<R (T::*)(ENF_TEPL_T_ARGS_0) ENF_COMM_SPTR_0 ENF_TEPL_ARGS_0> > bind(R (T::*f)(ENF_TEPL_T_ARGS_0), T *obj ENF_COMM_SPTR_0 ENF_CRPARAM_DEC_0)
{
	typedef R (T::*F)(ENF_TEPL_T_ARGS_0);
	typedef bindlist0<F ENF_COMM_SPTR_0 ENF_TEPL_ARGS_0> bindlist_type;
	//bindlist_type bl(f, obj ENF_COMM_SPTR_0 ENF_ARGS_0);
	return binder<bindlist_type>(bindlist_type(f, obj ENF_COMM_SPTR_0 ENF_ARGS_0));
}

template<typename R ENF_COMM_SPTR_1 ENF_TEPL_T_DEC_1 ENF_COMM_SPTR_1 ENF_TEPL_DEC_1>
binder<bindlist1<R (*)(ENF_TEPL_T_ARGS_1) ENF_COMM_SPTR_1 ENF_TEPL_ARGS_1> > bind(R (*f)(ENF_TEPL_T_ARGS_1) ENF_COMM_SPTR_1 ENF_CRPARAM_DEC_1)
{
	typedef R (*F)(ENF_TEPL_T_ARGS_1);
	typedef bindlist1<F ENF_COMM_SPTR_1 ENF_TEPL_ARGS_1> bindlist_type;
	//bindlist_type bl(f, 0 ENF_COMM_SPTR_1 ENF_ARGS_1);
	return binder<bindlist_type>(bindlist_type(f, 0 ENF_COMM_SPTR_1 ENF_ARGS_1));
}

template<typename R, typename T ENF_COMM_SPTR_1 ENF_TEPL_T_DEC_1 ENF_COMM_SPTR_1 ENF_TEPL_DEC_1>
binder<bindlist1<R (T::*)(ENF_TEPL_T_ARGS_1) ENF_COMM_SPTR_1 ENF_TEPL_ARGS_1> > bind(R (T::*f)(ENF_TEPL_T_ARGS_1), T *obj ENF_COMM_SPTR_1 ENF_CRPARAM_DEC_1)
{
	typedef R (T::*F)(ENF_TEPL_T_ARGS_1);
	typedef bindlist1<F ENF_COMM_SPTR_1 ENF_TEPL_ARGS_1> bindlist_type;
	//bindlist_type bl(f, obj ENF_COMM_SPTR_1 ENF_ARGS_1);
	return binder<bindlist_type>(bindlist_type(f, obj ENF_COMM_SPTR_1 ENF_ARGS_1));
}

template<typename R ENF_COMM_SPTR_2 ENF_TEPL_T_DEC_2 ENF_COMM_SPTR_2 ENF_TEPL_DEC_2>
binder<bindlist2<R (*)(ENF_TEPL_T_ARGS_2) ENF_COMM_SPTR_2 ENF_TEPL_ARGS_2> > bind(R (*f)(ENF_TEPL_T_ARGS_2) ENF_COMM_SPTR_2 ENF_CRPARAM_DEC_2)
{
	typedef R (*F)(ENF_TEPL_T_ARGS_2);
	typedef bindlist2<F ENF_COMM_SPTR_2 ENF_TEPL_ARGS_2> bindlist_type;
	//bindlist_type bl(f, 0 ENF_COMM_SPTR_2 ENF_ARGS_2);
	return binder<bindlist_type>(bindlist_type(f, 0 ENF_COMM_SPTR_2 ENF_ARGS_2));
}

template<typename R, typename T ENF_COMM_SPTR_2 ENF_TEPL_T_DEC_2 ENF_COMM_SPTR_2 ENF_TEPL_DEC_2>
binder<bindlist2<R (T::*)(ENF_TEPL_T_ARGS_2) ENF_COMM_SPTR_2 ENF_TEPL_ARGS_2> > bind(R (T::*f)(ENF_TEPL_T_ARGS_2), T *obj ENF_COMM_SPTR_2 ENF_CRPARAM_DEC_2)
{
	typedef R (T::*F)(ENF_TEPL_T_ARGS_2);
	typedef bindlist2<F ENF_COMM_SPTR_2 ENF_TEPL_ARGS_2> bindlist_type;
	//bindlist_type bl(f, obj ENF_COMM_SPTR_2 ENF_ARGS_2);
	return binder<bindlist_type>(bindlist_type(f, obj ENF_COMM_SPTR_2 ENF_ARGS_2));
}

template<typename R ENF_COMM_SPTR_3 ENF_TEPL_T_DEC_3 ENF_COMM_SPTR_3 ENF_TEPL_DEC_3>
binder<bindlist3<R (*)(ENF_TEPL_T_ARGS_3) ENF_COMM_SPTR_3 ENF_TEPL_ARGS_3> > bind(R (*f)(ENF_TEPL_T_ARGS_3) ENF_COMM_SPTR_3 ENF_CRPARAM_DEC_3)
{
	typedef R (*F)(ENF_TEPL_T_ARGS_3);
	typedef bindlist3<F ENF_COMM_SPTR_3 ENF_TEPL_ARGS_3> bindlist_type;
	//bindlist_type bl(f, 0 ENF_COMM_SPTR_3 ENF_ARGS_3);
	return binder<bindlist_type>(bindlist_type(f, 0 ENF_COMM_SPTR_3 ENF_ARGS_3));
}

template<typename R, typename T ENF_COMM_SPTR_3 ENF_TEPL_T_DEC_3 ENF_COMM_SPTR_3 ENF_TEPL_DEC_3>
binder<bindlist3<R (T::*)(ENF_TEPL_T_ARGS_3) ENF_COMM_SPTR_3 ENF_TEPL_ARGS_3> > bind(R (T::*f)(ENF_TEPL_T_ARGS_3), T *obj ENF_COMM_SPTR_3 ENF_CRPARAM_DEC_3)
{
	typedef R (T::*F)(ENF_TEPL_T_ARGS_3);
	typedef bindlist3<F ENF_COMM_SPTR_3 ENF_TEPL_ARGS_3> bindlist_type;
	//bindlist_type bl(f, obj ENF_COMM_SPTR_3 ENF_ARGS_3);
	return binder<bindlist_type>(bindlist_type(f, obj ENF_COMM_SPTR_3 ENF_ARGS_3));
}

template<typename R ENF_COMM_SPTR_4 ENF_TEPL_T_DEC_4 ENF_COMM_SPTR_4 ENF_TEPL_DEC_4>
binder<bindlist4<R (*)(ENF_TEPL_T_ARGS_4) ENF_COMM_SPTR_4 ENF_TEPL_ARGS_4> > bind(R (*f)(ENF_TEPL_T_ARGS_4) ENF_COMM_SPTR_4 ENF_CRPARAM_DEC_4)
{
	typedef R (*F)(ENF_TEPL_T_ARGS_4);
	typedef bindlist4<F ENF_COMM_SPTR_4 ENF_TEPL_ARGS_4> bindlist_type;
	//bindlist_type bl(f, 0 ENF_COMM_SPTR_4 ENF_ARGS_4);
	return binder<bindlist_type>(bindlist_type(f, 0 ENF_COMM_SPTR_4 ENF_ARGS_4));
}

template<typename R, typename T ENF_COMM_SPTR_4 ENF_TEPL_T_DEC_4 ENF_COMM_SPTR_4 ENF_TEPL_DEC_4>
binder<bindlist4<R (T::*)(ENF_TEPL_T_ARGS_4) ENF_COMM_SPTR_4 ENF_TEPL_ARGS_4> > bind(R (T::*f)(ENF_TEPL_T_ARGS_4), T *obj ENF_COMM_SPTR_4 ENF_CRPARAM_DEC_4)
{
	typedef R (T::*F)(ENF_TEPL_T_ARGS_4);
	typedef bindlist4<F ENF_COMM_SPTR_4 ENF_TEPL_ARGS_4> bindlist_type;
	//bindlist_type bl(f, obj ENF_COMM_SPTR_4 ENF_ARGS_4);
	return binder<bindlist_type>(bindlist_type(f, obj ENF_COMM_SPTR_4 ENF_ARGS_4));
}

template<typename R ENF_COMM_SPTR_5 ENF_TEPL_T_DEC_5 ENF_COMM_SPTR_5 ENF_TEPL_DEC_5>
binder<bindlist5<R (*)(ENF_TEPL_T_ARGS_5) ENF_COMM_SPTR_5 ENF_TEPL_ARGS_5> > bind(R (*f)(ENF_TEPL_T_ARGS_5) ENF_COMM_SPTR_5 ENF_CRPARAM_DEC_5)
{
	typedef R (*F)(ENF_TEPL_T_ARGS_5);
	typedef bindlist5<F ENF_COMM_SPTR_5 ENF_TEPL_ARGS_5> bindlist_type;
	//bindlist_type bl(f, 0 ENF_COMM_SPTR_5 ENF_ARGS_5);
	return binder<bindlist_type>(bindlist_type(f, 0 ENF_COMM_SPTR_5 ENF_ARGS_5));
}

template<typename R, typename T ENF_COMM_SPTR_5 ENF_TEPL_T_DEC_5 ENF_COMM_SPTR_5 ENF_TEPL_DEC_5>
binder<bindlist5<R (T::*)(ENF_TEPL_T_ARGS_5) ENF_COMM_SPTR_5 ENF_TEPL_ARGS_5> > bind(R (T::*f)(ENF_TEPL_T_ARGS_5), T *obj ENF_COMM_SPTR_5 ENF_CRPARAM_DEC_5)
{
	typedef R (T::*F)(ENF_TEPL_T_ARGS_5);
	typedef bindlist5<F ENF_COMM_SPTR_5 ENF_TEPL_ARGS_5> bindlist_type;
	//bindlist_type bl(f, obj ENF_COMM_SPTR_5 ENF_ARGS_5);
	return binder<bindlist_type>(bindlist_type(f, obj ENF_COMM_SPTR_5 ENF_ARGS_5));
}

template<typename R ENF_COMM_SPTR_6 ENF_TEPL_T_DEC_6 ENF_COMM_SPTR_6 ENF_TEPL_DEC_6>
binder<bindlist6<R (*)(ENF_TEPL_T_ARGS_6) ENF_COMM_SPTR_6 ENF_TEPL_ARGS_6> > bind(R (*f)(ENF_TEPL_T_ARGS_6) ENF_COMM_SPTR_6 ENF_CRPARAM_DEC_6)
{
	typedef R (*F)(ENF_TEPL_T_ARGS_6);
	typedef bindlist6<F ENF_COMM_SPTR_6 ENF_TEPL_ARGS_6> bindlist_type;
	//bindlist_type bl(f, 0 ENF_COMM_SPTR_6 ENF_ARGS_6);
	return binder<bindlist_type>(bindlist_type(f, 0 ENF_COMM_SPTR_6 ENF_ARGS_6));
}

template<typename R, typename T ENF_COMM_SPTR_6 ENF_TEPL_T_DEC_6 ENF_COMM_SPTR_6 ENF_TEPL_DEC_6>
binder<bindlist6<R (T::*)(ENF_TEPL_T_ARGS_6) ENF_COMM_SPTR_6 ENF_TEPL_ARGS_6> > bind(R (T::*f)(ENF_TEPL_T_ARGS_6), T *obj ENF_COMM_SPTR_6 ENF_CRPARAM_DEC_6)
{
	typedef R (T::*F)(ENF_TEPL_T_ARGS_6);
	typedef bindlist6<F ENF_COMM_SPTR_6 ENF_TEPL_ARGS_6> bindlist_type;
	//bindlist_type bl(f, obj ENF_COMM_SPTR_6 ENF_ARGS_6);
	return binder<bindlist_type>(bindlist_type(f, obj ENF_COMM_SPTR_6 ENF_ARGS_6));
}

template<typename R ENF_COMM_SPTR_7 ENF_TEPL_T_DEC_7 ENF_COMM_SPTR_7 ENF_TEPL_DEC_7>
binder<bindlist7<R (*)(ENF_TEPL_T_ARGS_7) ENF_COMM_SPTR_7 ENF_TEPL_ARGS_7> > bind(R (*f)(ENF_TEPL_T_ARGS_7) ENF_COMM_SPTR_7 ENF_CRPARAM_DEC_7)
{
	typedef R (*F)(ENF_TEPL_T_ARGS_7);
	typedef bindlist7<F ENF_COMM_SPTR_7 ENF_TEPL_ARGS_7> bindlist_type;
	//bindlist_type bl(f, 0 ENF_COMM_SPTR_7 ENF_ARGS_7);
	return binder<bindlist_type>(bindlist_type(f, 0 ENF_COMM_SPTR_7 ENF_ARGS_7));
}

template<typename R, typename T ENF_COMM_SPTR_7 ENF_TEPL_T_DEC_7 ENF_COMM_SPTR_7 ENF_TEPL_DEC_7>
binder<bindlist7<R (T::*)(ENF_TEPL_T_ARGS_7) ENF_COMM_SPTR_7 ENF_TEPL_ARGS_7> > bind(R (T::*f)(ENF_TEPL_T_ARGS_7), T *obj ENF_COMM_SPTR_7 ENF_CRPARAM_DEC_7)
{
	typedef R (T::*F)(ENF_TEPL_T_ARGS_7);
	typedef bindlist7<F ENF_COMM_SPTR_7 ENF_TEPL_ARGS_7> bindlist_type;
	//bindlist_type bl(f, obj ENF_COMM_SPTR_7 ENF_ARGS_7);
	return binder<bindlist_type>(bindlist_type(f, obj ENF_COMM_SPTR_7 ENF_ARGS_7));
}

template<typename R ENF_COMM_SPTR_8 ENF_TEPL_T_DEC_8 ENF_COMM_SPTR_8 ENF_TEPL_DEC_8>
binder<bindlist8<R (*)(ENF_TEPL_T_ARGS_8) ENF_COMM_SPTR_8 ENF_TEPL_ARGS_8> > bind(R (*f)(ENF_TEPL_T_ARGS_8) ENF_COMM_SPTR_8 ENF_CRPARAM_DEC_8)
{
	typedef R (*F)(ENF_TEPL_T_ARGS_8);
	typedef bindlist8<F ENF_COMM_SPTR_8 ENF_TEPL_ARGS_8> bindlist_type;
	//bindlist_type bl(f, 0 ENF_COMM_SPTR_8 ENF_ARGS_8);
	return binder<bindlist_type>(bindlist_type(f, 0 ENF_COMM_SPTR_8 ENF_ARGS_8));
}

template<typename R, typename T ENF_COMM_SPTR_8 ENF_TEPL_T_DEC_8 ENF_COMM_SPTR_8 ENF_TEPL_DEC_8>
binder<bindlist8<R (T::*)(ENF_TEPL_T_ARGS_8) ENF_COMM_SPTR_8 ENF_TEPL_ARGS_8> > bind(R (T::*f)(ENF_TEPL_T_ARGS_8), T *obj ENF_COMM_SPTR_8 ENF_CRPARAM_DEC_8)
{
	typedef R (T::*F)(ENF_TEPL_T_ARGS_8);
	typedef bindlist8<F ENF_COMM_SPTR_8 ENF_TEPL_ARGS_8> bindlist_type;
	//bindlist_type bl(f, obj ENF_COMM_SPTR_8 ENF_ARGS_8);
	return binder<bindlist_type>(bindlist_type(f, obj ENF_COMM_SPTR_8 ENF_ARGS_8));
}

template<typename R ENF_COMM_SPTR_9 ENF_TEPL_T_DEC_9 ENF_COMM_SPTR_9 ENF_TEPL_DEC_9>
binder<bindlist9<R (*)(ENF_TEPL_T_ARGS_9) ENF_COMM_SPTR_9 ENF_TEPL_ARGS_9> > bind(R (*f)(ENF_TEPL_T_ARGS_9) ENF_COMM_SPTR_9 ENF_CRPARAM_DEC_9)
{
	typedef R (*F)(ENF_TEPL_T_ARGS_9);
	typedef bindlist9<F ENF_COMM_SPTR_9 ENF_TEPL_ARGS_9> bindlist_type;
	//bindlist_type bl(f, 0 ENF_COMM_SPTR_9 ENF_ARGS_9);
	return binder<bindlist_type>(bindlist_type(f, 0 ENF_COMM_SPTR_9 ENF_ARGS_9));
}

template<typename R, typename T ENF_COMM_SPTR_9 ENF_TEPL_T_DEC_9 ENF_COMM_SPTR_9 ENF_TEPL_DEC_9>
binder<bindlist9<R (T::*)(ENF_TEPL_T_ARGS_9) ENF_COMM_SPTR_9 ENF_TEPL_ARGS_9> > bind(R (T::*f)(ENF_TEPL_T_ARGS_9), T *obj ENF_COMM_SPTR_9 ENF_CRPARAM_DEC_9)
{
	typedef R (T::*F)(ENF_TEPL_T_ARGS_9);
	typedef bindlist9<F ENF_COMM_SPTR_9 ENF_TEPL_ARGS_9> bindlist_type;
	//bindlist_type bl(f, obj ENF_COMM_SPTR_9 ENF_ARGS_9);
	return binder<bindlist_type>(bindlist_type(f, obj ENF_COMM_SPTR_9 ENF_ARGS_9));
}

} // namespace function

#endif
