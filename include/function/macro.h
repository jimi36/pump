/*
 * The MIT License (MIT)
 *
 * Copyright (C) zhenghaitao
 * Contact mail with ming8ren@163.com
 *
 */

#ifndef function_macro_h
#define function_macro_h

#define ENF_COMM_SPTR_0
#define ENF_COMM_SPTR_1 ,
#define ENF_COMM_SPTR_2 ,
#define ENF_COMM_SPTR_3 ,
#define ENF_COMM_SPTR_4 ,
#define ENF_COMM_SPTR_5 ,
#define ENF_COMM_SPTR_6 ,
#define ENF_COMM_SPTR_7 ,
#define ENF_COMM_SPTR_8 ,
#define ENF_COMM_SPTR_9 ,
#define ENF_COMM_SPTR_N(N) ENF_COMM_SPTR_##N

#define ENF_TEPL_DEC_0
#define ENF_TEPL_DEC_1 typename A1
#define ENF_TEPL_DEC_2 ENF_TEPL_DEC_1, typename A2
#define ENF_TEPL_DEC_3 ENF_TEPL_DEC_2, typename A3
#define ENF_TEPL_DEC_4 ENF_TEPL_DEC_3, typename A4
#define ENF_TEPL_DEC_5 ENF_TEPL_DEC_4, typename A5
#define ENF_TEPL_DEC_6 ENF_TEPL_DEC_5, typename A6
#define ENF_TEPL_DEC_7 ENF_TEPL_DEC_6, typename A7
#define ENF_TEPL_DEC_8 ENF_TEPL_DEC_7, typename A8
#define ENF_TEPL_DEC_9 ENF_TEPL_DEC_8, typename A9
#define ENF_TEPL_DEC_N(N) ENF_TEPL_DEC_##N

#define ENF_TEPL_ARGS_0 
#define ENF_TEPL_ARGS_1 A1
#define ENF_TEPL_ARGS_2 ENF_TEPL_ARGS_1, A2
#define ENF_TEPL_ARGS_3 ENF_TEPL_ARGS_2, A3
#define ENF_TEPL_ARGS_4 ENF_TEPL_ARGS_3, A4
#define ENF_TEPL_ARGS_5 ENF_TEPL_ARGS_4, A5
#define ENF_TEPL_ARGS_6 ENF_TEPL_ARGS_5, A6
#define ENF_TEPL_ARGS_7 ENF_TEPL_ARGS_6, A7
#define ENF_TEPL_ARGS_8 ENF_TEPL_ARGS_7, A8
#define ENF_TEPL_ARGS_9 ENF_TEPL_ARGS_8, A9
#define ENF_TEPL_ARGS_N(N) ENF_TEPL_ARGS_##N

#define ENF_TEPL_ARGS_QU_0 
#define ENF_TEPL_ARGS_QU_1 A1&
#define ENF_TEPL_ARGS_QU_2 ENF_TEPL_ARGS_QU_1, A2&
#define ENF_TEPL_ARGS_QU_3 ENF_TEPL_ARGS_QU_2, A3&
#define ENF_TEPL_ARGS_QU_4 ENF_TEPL_ARGS_QU_3, A4&
#define ENF_TEPL_ARGS_QU_5 ENF_TEPL_ARGS_QU_4, A5&
#define ENF_TEPL_ARGS_QU_6 ENF_TEPL_ARGS_QU_5, A6&
#define ENF_TEPL_ARGS_QU_7 ENF_TEPL_ARGS_QU_6, A7&
#define ENF_TEPL_ARGS_QU_8 ENF_TEPL_ARGS_QU_7, A8&
#define ENF_TEPL_ARGS_QU_9 ENF_TEPL_ARGS_QU_8, A9&
#define ENF_TEPL_ARGS_QU_N(N) ENF_TEPL_ARGS_QU_##N

#define ENF_CRPARAM_DEC_0
#define ENF_CRPARAM_DEC_1 const A1& a1
#define ENF_CRPARAM_DEC_2 ENF_CRPARAM_DEC_1 , const A2& a2
#define ENF_CRPARAM_DEC_3 ENF_CRPARAM_DEC_2 , const A3& a3
#define ENF_CRPARAM_DEC_4 ENF_CRPARAM_DEC_3 , const A4& a4
#define ENF_CRPARAM_DEC_5 ENF_CRPARAM_DEC_4 , const A5& a5
#define ENF_CRPARAM_DEC_6 ENF_CRPARAM_DEC_5 , const A6& a6
#define ENF_CRPARAM_DEC_7 ENF_CRPARAM_DEC_6 , const A7& a7
#define ENF_CRPARAM_DEC_8 ENF_CRPARAM_DEC_7 , const A8& a8
#define ENF_CRPARAM_DEC_9 ENF_CRPARAM_DEC_8 , const A9& a9
#define ENF_CRPARAM_DEC_N(N) ENF_CRPARAM_DEC_##N

#define ENF_CRPARAM_DEC_NC_0
#define ENF_CRPARAM_DEC_NC_1 A1& a1
#define ENF_CRPARAM_DEC_NC_2 ENF_CRPARAM_DEC_NC_1 , A2& a2
#define ENF_CRPARAM_DEC_NC_3 ENF_CRPARAM_DEC_NC_2 , A3& a3
#define ENF_CRPARAM_DEC_NC_4 ENF_CRPARAM_DEC_NC_3 , A4& a4
#define ENF_CRPARAM_DEC_NC_5 ENF_CRPARAM_DEC_NC_4 , A5& a5
#define ENF_CRPARAM_DEC_NC_6 ENF_CRPARAM_DEC_NC_5 , A6& a6
#define ENF_CRPARAM_DEC_NC_7 ENF_CRPARAM_DEC_NC_6 , A7& a7
#define ENF_CRPARAM_DEC_NC_8 ENF_CRPARAM_DEC_NC_7 , A8& a8
#define ENF_CRPARAM_DEC_NC_9 ENF_CRPARAM_DEC_NC_8 , A9& a9
#define ENF_CRPARAM_DEC_NC_N(N) ENF_CRPARAM_DEC_NC_##N

#define ENF_PARAM_DEC_0
#define ENF_PARAM_DEC_1 A1 a1
#define ENF_PARAM_DEC_2 ENF_PARAM_DEC_1 , A2 a2
#define ENF_PARAM_DEC_3 ENF_PARAM_DEC_2 , A3 a3
#define ENF_PARAM_DEC_4 ENF_PARAM_DEC_3 , A4 a4
#define ENF_PARAM_DEC_5 ENF_PARAM_DEC_4 , A5 a5
#define ENF_PARAM_DEC_6 ENF_PARAM_DEC_5 , A6 a6
#define ENF_PARAM_DEC_7 ENF_PARAM_DEC_6 , A7 a7
#define ENF_PARAM_DEC_8 ENF_PARAM_DEC_7 , A8 a8
#define ENF_PARAM_DEC_9 ENF_PARAM_DEC_8 , A9 a9

#define ENF_ARGS_0
#define ENF_ARGS_1 a1
#define ENF_ARGS_2 ENF_ARGS_1 , a2
#define ENF_ARGS_3 ENF_ARGS_2 , a3
#define ENF_ARGS_4 ENF_ARGS_3 , a4
#define ENF_ARGS_5 ENF_ARGS_4 , a5
#define ENF_ARGS_6 ENF_ARGS_5 , a6
#define ENF_ARGS_7 ENF_ARGS_6 , a7
#define ENF_ARGS_8 ENF_ARGS_7 , a8
#define ENF_ARGS_9 ENF_ARGS_8 , a9
#define ENF_ARGS_N(N) ENF_ARGS_##N

#define ENF_TEPL_T_DEC_0
#define ENF_TEPL_T_DEC_1 typename T1
#define ENF_TEPL_T_DEC_2 ENF_TEPL_T_DEC_1, typename T2
#define ENF_TEPL_T_DEC_3 ENF_TEPL_T_DEC_2, typename T3
#define ENF_TEPL_T_DEC_4 ENF_TEPL_T_DEC_3, typename T4
#define ENF_TEPL_T_DEC_5 ENF_TEPL_T_DEC_4, typename T5
#define ENF_TEPL_T_DEC_6 ENF_TEPL_T_DEC_5, typename T6
#define ENF_TEPL_T_DEC_7 ENF_TEPL_T_DEC_6, typename T7
#define ENF_TEPL_T_DEC_8 ENF_TEPL_T_DEC_7, typename T8
#define ENF_TEPL_T_DEC_9 ENF_TEPL_T_DEC_8, typename T9

#define ENF_TEPL_T_ARGS_0 
#define ENF_TEPL_T_ARGS_1 T1
#define ENF_TEPL_T_ARGS_2 ENF_TEPL_T_ARGS_1, T2
#define ENF_TEPL_T_ARGS_3 ENF_TEPL_T_ARGS_2, T3
#define ENF_TEPL_T_ARGS_4 ENF_TEPL_T_ARGS_3, T4
#define ENF_TEPL_T_ARGS_5 ENF_TEPL_T_ARGS_4, T5
#define ENF_TEPL_T_ARGS_6 ENF_TEPL_T_ARGS_5, T6
#define ENF_TEPL_T_ARGS_7 ENF_TEPL_T_ARGS_6, T7
#define ENF_TEPL_T_ARGS_8 ENF_TEPL_T_ARGS_7, T8
#define ENF_TEPL_T_ARGS_9 ENF_TEPL_T_ARGS_8, T9

#define ENF_PLACE_HOLDERS_0
#define ENF_PLACE_HOLDERS_1 _1
#define ENF_PLACE_HOLDERS_2 ENF_PLACE_HOLDERS_1, _2
#define ENF_PLACE_HOLDERS_3 ENF_PLACE_HOLDERS_2, _3
#define ENF_PLACE_HOLDERS_4 ENF_PLACE_HOLDERS_3, _4
#define ENF_PLACE_HOLDERS_5 ENF_PLACE_HOLDERS_4, _5
#define ENF_PLACE_HOLDERS_6 ENF_PLACE_HOLDERS_5, _6
#define ENF_PLACE_HOLDERS_7 ENF_PLACE_HOLDERS_6, _7
#define ENF_PLACE_HOLDERS_8 ENF_PLACE_HOLDERS_7, _8
#define ENF_PLACE_HOLDERS_9 ENF_PLACE_HOLDERS_8, _9
#define ENF_PLACE_HOLDERS_N(N) ENF_PLACE_HOLDERS_##N

#define ENF_INPUT_ARGS_0(cl)
#define ENF_INPUT_ARGS_1(cl) cl[this->a1_]
#define ENF_INPUT_ARGS_2(cl) ENF_INPUT_ARGS_1(cl), cl[this->a2_]
#define ENF_INPUT_ARGS_3(cl) ENF_INPUT_ARGS_2(cl), cl[this->a3_]
#define ENF_INPUT_ARGS_4(cl) ENF_INPUT_ARGS_3(cl), cl[this->a4_]
#define ENF_INPUT_ARGS_5(cl) ENF_INPUT_ARGS_4(cl), cl[this->a5_]
#define ENF_INPUT_ARGS_6(cl) ENF_INPUT_ARGS_5(cl), cl[this->a6_]
#define ENF_INPUT_ARGS_7(cl) ENF_INPUT_ARGS_6(cl), cl[this->a7_]
#define ENF_INPUT_ARGS_8(cl) ENF_INPUT_ARGS_7(cl), cl[this->a8_]
#define ENF_INPUT_ARGS_9(cl) ENF_INPUT_ARGS_8(cl), cl[this->a9_]

template<int I> struct place_holder{};
static place_holder<1> _1;
static place_holder<2> _2;
static place_holder<3> _3;
static place_holder<4> _4;
static place_holder<5> _5;
static place_holder<6> _6;
static place_holder<7> _7;
static place_holder<8> _8;
static place_holder<9> _9;

#endif
