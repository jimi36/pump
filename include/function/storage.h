/*
 * The MIT License (MIT)
 *
 * Copyright (C) zhenghaitao
 * Contact mail with ming8ren@163.com
 *
 */

#ifndef function_storage_h
#define function_storage_h

#include "macro.h"

namespace function {

struct en_storage0
{
};

template<ENF_TEPL_DEC_1>
struct en_storage1: public en_storage0
{
	en_storage1(ENF_CRPARAM_DEC_1): a1_(a1) {}
	A1 a1_;
};

template<ENF_TEPL_DEC_2>
struct en_storage2: public en_storage1<ENF_TEPL_ARGS_1>
{
	en_storage2(ENF_CRPARAM_DEC_2): en_storage1<ENF_TEPL_ARGS_1>(ENF_ARGS_1), a2_(a2) {}
	A2 a2_;
};

template<ENF_TEPL_DEC_3>
struct en_storage3: public en_storage2<ENF_TEPL_ARGS_2>
{
	en_storage3(ENF_CRPARAM_DEC_3): en_storage2<ENF_TEPL_ARGS_2>(ENF_ARGS_2), a3_(a3) {}
	A3 a3_;
};

template<ENF_TEPL_DEC_4>
struct en_storage4: public en_storage3<ENF_TEPL_ARGS_3>
{
	en_storage4(ENF_CRPARAM_DEC_4): en_storage3<ENF_TEPL_ARGS_3>(ENF_ARGS_3), a4_(a4) {}
	A4 a4_;
};

template<ENF_TEPL_DEC_5>
struct en_storage5: public en_storage4<ENF_TEPL_ARGS_4>
{
	en_storage5(ENF_CRPARAM_DEC_5): en_storage4<ENF_TEPL_ARGS_4>(ENF_ARGS_4), a5_(a5) {}
	A5 a5_;
};

template<ENF_TEPL_DEC_6>
struct en_storage6: public en_storage5<ENF_TEPL_ARGS_5>
{
	en_storage6(ENF_CRPARAM_DEC_6): en_storage5<ENF_TEPL_ARGS_5>(ENF_ARGS_5), a6_(a6) {}
	A6 a6_;
};

template<ENF_TEPL_DEC_7>
struct en_storage7: public en_storage6<ENF_TEPL_ARGS_6>
{
	en_storage7(ENF_CRPARAM_DEC_7): en_storage6<ENF_TEPL_ARGS_6>(ENF_ARGS_6), a7_(a7) {}
	A7 a7_;
};

template<ENF_TEPL_DEC_8>
struct en_storage8: public en_storage7<ENF_TEPL_ARGS_7>
{
	en_storage8(ENF_CRPARAM_DEC_8): en_storage7<ENF_TEPL_ARGS_7>(ENF_ARGS_7), a8_(a8) {}
	A8 a8_;
};

template<ENF_TEPL_DEC_9>
struct en_storage9: public en_storage8<ENF_TEPL_ARGS_8>
{
	en_storage9(ENF_CRPARAM_DEC_9): en_storage8<ENF_TEPL_ARGS_8>(ENF_ARGS_8), a9_(a9) {}
	A9 a9_;
};

} // namespace function

#endif