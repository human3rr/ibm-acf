
#include "CeLoginUtil.h"

#include <CeLogin.h>

#ifndef _CELOGINJSON_H
#define _CELOGINJSON_H

namespace CeLogin
{

extern const char* JsonName_Version;
extern const char* JsonName_Machines;
extern const char* JsonName_HashedAuthCode;
extern const char* JsonName_Salt;
extern const char* JsonName_Expiration;
extern const char* JsonName_FrameworkEc;
extern const char* JsonName_SerialNumber;
extern const char* JsonName_RequestId;
extern const char* JsonName_Iterations;

struct CeLoginJsonData
{
    unsigned int version;
    ServiceAuthority mRequestedAuthority;
    uint8_t mHashedAuthCode[CeLogin_MaxHashedAuthCodeLength];
    uint64_t mHashedAuthCodeLength;
    uint8_t mAuthCodeSalt[CeLogin_MaxHashedAuthCodeSaltLength];
    uint64_t mAuthCodeSaltLength;
    CeLogin_Date mExpirationDate;
    uint64_t mIterations;
};

CeLoginRc decodeJson(const char* jsonStringParm,
                     const uint64_t jsonStringLengthParm,
                     const char* serialNumberParm,
                     const uint64_t serialNumberLengthParm,
                     CeLoginJsonData& decodedJsonParm);

CeLoginRc isTimeExpired(
    CeLoginJsonData *sJsonData, 
    uint64_t &sExpirationTime, 
    const uint64_t timeSinceUnixEpocInSecondsParm
);

}; // namespace CeLogin

#endif