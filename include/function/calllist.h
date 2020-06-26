/*
 * The MIT License (MIT)
 *
 * Copyright (C) zhenghaitao
 * Contact mail with ming8ren@163.com
 *
 */

#ifndef function_calllist_h
#define function_calllist_h

#include "storage.h"

namespace function {

#define __CALLLIST_SUBOPT_COMM() \
	template<typename T> T & operator [](T& t) { return t; }

#define __CALLLIST_SUBOPT(N) \
	A##N & operator [](place_holder<N>) { return this->a##N##_; }

#define CREATE_CALLLIST_SUBOPT_0 __CALLLIST_SUBOPT_COMM()
#define CREATE_CALLLIST_SUBOPT_1 CREATE_CALLLIST_SUBOPT_0 __CALLLIST_SUBOPT(1)
#define CREATE_CALLLIST_SUBOPT_2 CREATE_CALLLIST_SUBOPT_1 __CALLLIST_SUBOPT(2)
#define CREATE_CALLLIST_SUBOPT_3 CREATE_CALLLIST_SUBOPT_2 __CALLLIST_SUBOPT(3)
#define CREATE_CALLLIST_SUBOPT_4 CREATE_CALLLIST_SUBOPT_3 __CALLLIST_SUBOPT(4)
#define CREATE_CALLLIST_SUBOPT_5 CREATE_CALLLIST_SUBOPT_4 __CALLLIST_SUBOPT(5)
#define CREATE_CALLLIST_SUBOPT_6 CREATE_CALLLIST_SUBOPT_5 __CALLLIST_SUBOPT(6)
#define CREATE_CALLLIST_SUBOPT_7 CREATE_CALLLIST_SUBOPT_6 __CALLLIST_SUBOPT(7)
#define CREATE_CALLLIST_SUBOPT_8 CREATE_CALLLIST_SUBOPT_7 __CALLLIST_SUBOPT(8)
#define CREATE_CALLLIST_SUBOPT_9 CREATE_CALLLIST_SUBOPT_8 __CALLLIST_SUBOPT(9)

class calllist0 : public en_storage0
{
public:
	calllist0() {}

public:
	CREATE_CALLLIST_SUBOPT_0;
};

template<ENF_TEPL_DEC_1>
class calllist1: public en_storage1<ENF_TEPL_ARGS_1>
{
public:
	calllist1(ENF_CRPARAM_DEC_1): en_storage1<ENF_TEPL_ARGS_1>(ENF_ARGS_1) {}

public:
	CREATE_CALLLIST_SUBOPT_1
};

template<ENF_TEPL_DEC_2>
class calllist2: public en_storage2<ENF_TEPL_ARGS_2>
{
public:
	calllist2(ENF_CRPARAM_DEC_2): en_storage2<ENF_TEPL_ARGS_2>(ENF_ARGS_2) {}

public:
	CREATE_CALLLIST_SUBOPT_2;
};

template<ENF_TEPL_DEC_3>
class calllist3: public en_storage3<ENF_TEPL_ARGS_3>
{
public:
	calllist3(ENF_CRPARAM_DEC_3): en_storage3<ENF_TEPL_ARGS_3>(ENF_ARGS_3) {}

public:
	CREATE_CALLLIST_SUBOPT_3;
};

template<ENF_TEPL_DEC_4>
class calllist4: public en_storage4<ENF_TEPL_ARGS_4>
{
public:
	calllist4(ENF_CRPARAM_DEC_4): en_storage4<ENF_TEPL_ARGS_4>(ENF_ARGS_4) {}

public:
	CREATE_CALLLIST_SUBOPT_4;
};

template<ENF_TEPL_DEC_5>
class calllist5: public en_storage5<ENF_TEPL_ARGS_5>
{
public:
	calllist5(ENF_CRPARAM_DEC_5): en_storage5<ENF_TEPL_ARGS_5>(ENF_ARGS_5) {}

public:
	CREATE_CALLLIST_SUBOPT_5;
};

template<ENF_TEPL_DEC_6>
class calllist6: public en_storage6<ENF_TEPL_ARGS_6>
{
public:
	calllist6(ENF_CRPARAM_DEC_6): en_storage6<ENF_TEPL_ARGS_6>(ENF_ARGS_6) {}

public:
	CREATE_CALLLIST_SUBOPT_6;
};

template<ENF_TEPL_DEC_7>
class calllist7: public en_storage7<ENF_TEPL_ARGS_7>
{
public:
	calllist7(ENF_CRPARAM_DEC_7): en_storage7<ENF_TEPL_ARGS_7>(ENF_ARGS_7) {}

public:
	CREATE_CALLLIST_SUBOPT_7;
};

template<ENF_TEPL_DEC_8>
class calllist8: public en_storage8<ENF_TEPL_ARGS_8>
{
public:
	calllist8(ENF_CRPARAM_DEC_8): en_storage8<ENF_TEPL_ARGS_8>(ENF_ARGS_8) {}

public:
	CREATE_CALLLIST_SUBOPT_8;
};

template<ENF_TEPL_DEC_9>
class calllist9: public en_storage9<ENF_TEPL_ARGS_9>
{
public:
	calllist9(ENF_CRPARAM_DEC_9): en_storage9<ENF_TEPL_ARGS_9>(ENF_ARGS_9) {}

public:
	CREATE_CALLLIST_SUBOPT_9;
};

} // namespace function

#endif
