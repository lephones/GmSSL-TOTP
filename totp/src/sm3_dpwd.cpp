#include <stdio.h>
#include <string.h>
#include <math.h>
#include <stdint.h>
#include "sm3.h"
#include "sm_dpwd.h"

#define sm_word uint32_t

#ifdef __cplusplus
#define INLINE inline
#else
#define INLINE
#endif

#define IN    // 输入参数
#define OUT   // 输出参数
#define INOUT // 输入输出参数

INLINE bool IsBigEndian()
{
    union T
    {
        char c[2];
        short s;
    };

    T t;
    t.s = 0x0031;
    if (t.c[1] == 0x31)
    {
        return true;
    }
    return false;
}

INLINE bool IsLittleEndian()
{
    return !IsBigEndian();
}

INLINE uint32 Reverse32(uint32 x)
{
    return ((x & 0x000000ff) << 24) | ((x & 0x0000ff00) << 8) | ((x & 0x00ff0000) >> 8) | ((x & 0xff000000) >> 24);
}

INLINE uint64 Reverse64(uint64 x)
{
    uint32 nTemp[3] = {0};
    memcpy(nTemp + 1, &x, sizeof(uint64));
    nTemp[0] = Reverse32(nTemp[2]);
    nTemp[1] = Reverse32(nTemp[1]);
    return *(uint64 *)nTemp;
}

INLINE sm_word ML(byte X, uint8 j)
{
    if (IsBigEndian())
    {
        return (sm_word)(X << (j % 32));
    }
    else
    {
        return Reverse32((sm_word)(X << (j % 32)));
    }
}

INLINE sm_word SUM(sm_word X, sm_word Y)
{
    if (IsBigEndian())
    {
        return (X + Y);
    }
    else
    {
        return Reverse32(Reverse32(X) + Reverse32(Y));
    }
}

int TruncateSM3(IN byte pSrc[32], IN int nSrcLen, OUT byte pDst[4], IN int nDstSize)
{
    if (nSrcLen != 32 || nDstSize < 4)
    {
        return -1;
    }
    memset(pDst, 0, nDstSize);

    byte *S = (byte *)pSrc;
    sm_word S1 = ML(S[0], 24) | ML(S[1], 16) | ML(S[2], 8) | ML(S[3], 0);
    sm_word S2 = ML(S[4], 24) | ML(S[5], 16) | ML(S[6], 8) | ML(S[7], 0);
    sm_word S3 = ML(S[8], 24) | ML(S[9], 16) | ML(S[10], 8) | ML(S[11], 0);
    sm_word S4 = ML(S[12], 24) | ML(S[13], 16) | ML(S[14], 8) | ML(S[15], 0);
    sm_word S5 = ML(S[16], 24) | ML(S[17], 16) | ML(S[18], 8) | ML(S[19], 0);
    sm_word S6 = ML(S[20], 24) | ML(S[21], 16) | ML(S[22], 8) | ML(S[23], 0);
    sm_word S7 = ML(S[24], 24) | ML(S[25], 16) | ML(S[26], 8) | ML(S[27], 0);
    sm_word S8 = ML(S[28], 24) | ML(S[29], 16) | ML(S[30], 8) | ML(S[31], 0);

    sm_word OD = SUM(SUM(SUM(SUM(SUM(SUM(SUM(S1, S2), S3), S4), S5), S6), S7), S8);
    memcpy(pDst, &OD, sizeof(sm_word));

    return 0;
}

#define SM_DPWD_KEY_LEN_MIN (128 / 8)
#define SM_DPWD_CHALLENGE_LEN_MIN (4)
#define SM_DPWD_LEN_MAX (10)
#define SM_HASH_OUT_LEN (32)

int SM3_DPasswd(IN byte *pKey, IN int nKeyLen, IN uint64 *pTime, IN uint64 *pInterval, IN uint32 *pCounter,
                IN char *pChallenge, IN int nGenLen, OUT char *pDynPwd, IN int nDynPwdSize)
{
    if (pKey == NULL || (pTime == NULL && pCounter == NULL && pChallenge == NULL) || pDynPwd == NULL || nKeyLen < SM_DPWD_KEY_LEN_MIN || nGenLen > SM_DPWD_LEN_MAX || (pChallenge != NULL && strlen(pChallenge) < SM_DPWD_CHALLENGE_LEN_MIN) || nDynPwdSize < nGenLen + 1)
    {
        return SM_DPWD_PARAM_ERROR;
    }
    memset(pDynPwd, 0, nDynPwdSize);

    // T=To/Tc
    if (pTime != NULL && pInterval != NULL && *pInterval != 0)
    {
        *pTime = (*pTime) / (*pInterval);
    }

    // Convert to big-endian.
    if (!IsBigEndian())
    {
        if (pTime != NULL)
        {
            *pTime = Reverse64(*pTime);
        }
        if (pCounter != NULL)
        {
            *pCounter = Reverse32(*pCounter);
        }
    }

    int offset = 0;
    byte *sm_i = NULL;
    byte sm_o[SM_HASH_OUT_LEN] = {0};
    int sm_i_len = 0;
    int sm_o_len = sizeof(sm_o);
    uint32 pwd = {0};

    // ID(T|C|Q) Length at least 128 bits
    sm_i_len = (pTime ? sizeof(uint64) : 0) + (pCounter ? sizeof(uint32) : 0) +
               (pChallenge ? strlen(pChallenge) : 0);
    if (sm_i_len < 16)
    {
        // Fill ID to 128 bits with 0 at the end.
        sm_i_len = 16;
    }
    sm_i_len += nKeyLen;

    // Allocate IN-Data memory.
    sm_i = new byte[sm_i_len];
    if (sm_i == NULL)
    {
        return -2;
    }
    memset(sm_i, 0, sm_i_len);

    // 1. KEY|ID(T|C|Q)
    memcpy(sm_i, pKey, nKeyLen);
    offset = nKeyLen;
    if (pTime != NULL)
    {
        memcpy(sm_i + offset, pTime, sizeof(uint64));
        offset += sizeof(uint64);
    }
    if (pCounter != NULL)
    {
        memcpy(sm_i + offset, pCounter, sizeof(uint32));
        offset += sizeof(uint32);
    }
    if (pChallenge != NULL)
    {
        memcpy(sm_i + offset, pChallenge, strlen(pChallenge));
    }

    // 2. SM3
    // 创建 SM3_CTX 结构体并初始化
    SM3_CTX ctx;
    sm3_init(&ctx);
    // 更新哈希数据
    sm3_update(&ctx, sm_i, sm_i_len);
    byte hash[32];
    sm3_finish(&ctx, hash);

    // 3. Truncate
    TruncateSM3(hash, 32, (byte *)&pwd, sizeof(pwd));

#ifdef __SM_DBG_OUT
    ___DInit();
    ___DAdd("     K :[%s]\r\n", ___S2M(pKey, nKeyLen));
    ___DAdd("     T :[%016s]\r\n", ___S2M(pTime, 8));
    ___DAdd("     C :[%08s]\r\n", ___S2M(pCounter, 4));
    ___DAdd("     Q :[%s]\r\n", ___S2M(pChallenge, pChallenge == NULL ? 0 : strlen(pChallenge)));
    ___DAdd("SM3-IN :[%s]\r\n", ___S2M(sm_i, sm_i_len));
    ___DAdd("SM3-OUT:[%s]\r\n", ___S2M(sm_o, sm_o_len));
    ___DAdd("   Cut :[%s]\r\n", ___S2M(&pwd, sizeof(pwd)));
#endif //__SM_DBG_OUT

    // 4. MOD
    if (!IsBigEndian())
    {
        pwd = Reverse32(pwd);
    }
    pwd = pwd % (int)pow(10, nGenLen);

    // Output
    char szFmt[32] = {0};
    sprintf(szFmt, "%%0%dd", nGenLen);
    sprintf(pDynPwd, szFmt, pwd);

    delete[] sm_i;
    return pwd;
}
