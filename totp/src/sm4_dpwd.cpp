#include <stdio.h>
#include <string.h>
#include <math.h>
#include "sm4.h"
#include "sm_dpwd.h"

#ifdef __cplusplus
#define INLINE inline
#else
#define INLINE
#endif

#ifndef max
#define max(a, b) (((a) > (b)) ? (a) : (b))
#endif
#ifndef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#endif

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

int TruncateSM4(IN byte pSrc[16], IN int nSrcLen, OUT byte pDst[4], IN int nDstSize)
{
    if (nSrcLen != 16 || nDstSize < 4)
    {
        return -1;
    }
    memset(pDst, 0, nDstSize);

    byte *S = (byte *)pSrc;
    sm_word S1 = ML(S[0], 24) | ML(S[1], 16) | ML(S[2], 8) | ML(S[3], 0);
    sm_word S2 = ML(S[4], 24) | ML(S[5], 16) | ML(S[6], 8) | ML(S[7], 0);
    sm_word S3 = ML(S[8], 24) | ML(S[9], 16) | ML(S[10], 8) | ML(S[11], 0);
    sm_word S4 = ML(S[12], 24) | ML(S[13], 16) | ML(S[14], 8) | ML(S[15], 0);

    sm_word OD = SUM(SUM(SUM(S1, S2), S3), S4);
    memcpy(pDst, &OD, sizeof(sm_word));

    return 0;
}

int SM4_Encrypt(const uint8_t *sm_k, size_t sm_k_len,
                const uint8_t *sm_i, size_t sm_i_len,
                uint8_t *sm_o, int sm_o_len) {

    SM4_KEY sm4_key;
    sm4_set_encrypt_key(&sm4_key, sm_k);

    // 执行 SM4 加密（分组长度固定为 16 字节）
    sm4_encrypt(&sm4_key, sm_i, sm_o);

    return 0; // 成功
}

int SM4_DPasswd(IN byte *pKey, IN int nKeyLen, IN uint64 *pTime, IN uint64 *pInterval, IN uint32 *pCounter,
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
    byte *sm_buf = NULL;
    byte *sm_k = NULL;
    byte *sm_i = NULL;
    byte sm_o[16] = {0};
    int sm_k_len = 0;
    int sm_i_len = 0;
    int sm_o_len = sizeof(sm_o);
    uint32 pwd = {0};

    // If length of Key is not multiple of 128 bits, extend it to multiple of 128 with 0.
    sm_k_len = nKeyLen;
    if (sm_k_len % 16 != 0)
    {
        sm_k_len += 16 - sm_k_len % 16;
    }

    // If length of ID(T|C|Q) is not multiple of 128 bits, extend it to multiple of 128 with 0.
    sm_i_len = (pTime ? sizeof(uint64) : 0) + (pCounter ? sizeof(uint32) : 0) + (pChallenge ? strlen(pChallenge) : 0);
    if (sm_i_len % 16 != 0)
    {
        sm_i_len += 16 - sm_i_len % 16;
    }

    // Allocate SM4 buffer(KEY and ID) memory.
    sm_buf = new byte[sm_k_len + sm_i_len];
    if (sm_buf == NULL)
    {
        return SM_DPWD_NO_MEMORY;
    }
    memset(sm_buf, 0, sm_k_len + sm_i_len);
    sm_k = sm_buf;
    sm_i = sm_buf + sm_k_len;

    // KEY
    memcpy(sm_k, pKey, nKeyLen);

    // ID = T|C|Q
    if (pTime != NULL)
    {
        memcpy(sm_i, pTime, sizeof(uint64));
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

    int k_cnt = sm_k_len / 16;
    int i_cnt = sm_i_len / 16;
    int _cnt = max(k_cnt, i_cnt);

#ifdef __SM_DBG_OUT
    ___Dump("     K :[%s]\r\n", ___S2M(pKey, nKeyLen));
    ___Dump("     T :[%016s]\r\n", ___S2M(pTime, 8));
    ___Dump("     C :[%08s]\r\n", ___S2M(pCounter, 4));
    ___Dump("     Q :[%s]\r\n", ___S2M(pChallenge, pChallenge == NULL ? 0 : strlen(pChallenge)));
#endif //__SM_DBG_OUT

    for (int i = 0; i < _cnt; ++i)
    {
        int rc = SM4_Encrypt(sm_k, 16, sm_i, 16, sm_o, sm_o_len);
        if (rc < 0)
        {
            return rc;
        }

#ifdef __SM_DBG_OUT
        ___Dump("SM4-IN :[%s]\r\n", ___S2M(sm_i, 16));
        ___Dump("SM4-OUT:[%s]\r\n", ___S2M(sm_o, sm_o_len));
#endif //__SM_DBG_OUT

        int j, k;
        uint8 overflow;

        // 'out' + next 16 bytes 'key'.
        overflow = 0;
        k = min(i + 1, k_cnt - 1);
        for (j = 15; j >= 0; --j)
        {
            uint16 sum = sm_o[j] + sm_k[16 * k + j] + overflow;
            sm_k[j] = (uint8)sum;
            overflow = (uint8)(sum >> 8);
        }

        // 'out' + next 16 bytes 'in'.
        overflow = 0;
        k = min(i + 1, i_cnt - 1);
        for (j = 15; j >= 0; --j)
        {
            uint16 sum = sm_o[j] + sm_i[16 * k + j] + overflow;
            sm_i[j] = (uint8)sum;
            overflow = (uint8)(sum >> 8);
        }
    }

    TruncateSM4(sm_o, sm_o_len, (byte *)&pwd, sizeof(pwd));

#ifdef __SM_DBG_OUT
    ___Dump("   Cut :[%s]\r\n", ___S2M(&pwd, sizeof(pwd)));
#endif //__SM_DBG_OUT

    if (!IsBigEndian())
    {
        pwd = Reverse32(pwd);
    }
    pwd = pwd % (int)pow(10, nGenLen);

    char szFmt[32] = {0};
    sprintf(szFmt, "%%0%dd", nGenLen);
    sprintf(pDynPwd, szFmt, pwd);

    delete[] sm_buf;
    return 0;
}
