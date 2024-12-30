//
// Created by lephones on 2024/12/30.
//

#ifndef GMSSL_SMDPWD_H
#define GMSSL_SMDPWD_H

#endif //GMSSL_SMDPWD_H

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <stdint.h>
#include "sm3.h"

#define  sm_word			uint32_t

#ifdef __cplusplus
#  define INLINE inline
#else
#  define INLINE
#endif

#define IN    // 输入参数
#define OUT   // 输出参数
#define INOUT // 输入输出参数


typedef uint64_t uint64;
typedef uint32_t uint32;
typedef uint8_t byte;  // 定义 byte 为无符号 8 位整数
typedef unsigned short uint16; // 定义 short 为无符号 16 位整数
typedef uint8_t uint8 ; // 定义 byte 为无符号 8 位整数
typedef  uint8 ; // 定义 byte 为无符号 8 位整数

#define SM_DPWD_KEY_LEN_MIN (128 / 8)
#define SM_DPWD_CHALLENGE_LEN_MIN (4)
#define SM_DPWD_LEN_MAX (10)
#define SM_HASH_OUT_LEN (32)

int TruncateSM3(IN byte pSrc[32], IN int nSrcLen, OUT byte pDst[4], IN int nDstSize);

#define SM_DPWD_KEY_LEN_MIN         (128/8)
#define SM_DPWD_CHALLENGE_LEN_MIN   (4)
#define SM_DPWD_LEN_MAX             (10)
#define SM_HASH_OUT_LEN             (32)
#define SM_DPWD_PARAM_ERROR             (-1)
#define SM_DPWD_NO_MEMORY             (-2)

int SM3_DPasswd(IN byte* pKey, IN int nKeyLen, IN uint64* pTime, IN uint64* pInterval, IN uint32* pCounter,
                IN char* pChallenge, IN int nGenLen, OUT char* pDynPwd, IN int nDynPwdSize);

int TruncateSM4(IN byte pSrc[16], IN int nSrcLen, OUT byte pDst[4], IN int nDstSize);

int SM4_DPasswd(IN byte* pKey, IN int nKeyLen, IN uint64* pTime, IN uint64* pInterval, IN uint32* pCounter,
                IN char* pChallenge, IN int nGenLen, OUT char* pDynPwd, IN int nDynPwdSize);
int SM4_Encrypt(const uint8_t *sm_k, size_t sm_k_len,
                const uint8_t *sm_i, size_t sm_i_len,
                uint8_t *sm_o, size_t *sm_o_len);

