
#include <stdint.h>

#ifndef _CELOGIN_H
#define _CELOGIN_H

namespace CeLogin
{

extern const char* AcfProcessingType;

enum ServiceAuthority
{
    ServiceAuth_None = 0,
    ServiceAuth_User = 10, ///< Customer level
    ServiceAuth_CE = 20,   ///< CE/SSR level
    ServiceAuth_Dev = 30,  ///< Developer/Support level
};

enum
{
    CeLoginInvalidVersion = 0,
    CeLoginVersion1 = 1,
    CeLogin_PBKDF2_Iterations = 100000,
};

struct CeLoginRc
{
    enum Component
    {
        Base = 0,
        JsonUtils = 1, // Implementation Specific
        JsmnUtils = 2, // Implementation Specific

        // Must fit in 1 byte
    };

    enum RcBase
    {
        Success = 0x00,
        Failure = 0x01,
        UnsupportedVersion = 0x02,
        SignatureNotValid = 0x03,
        PasswordNotValid = 0x04,
        AcfExpired = 0x05,
        SerialNumberMismatch = 0x06,
        JsonDataAllocationFailure = 0x07,

        CreateHsf_PasswordHashFailure = 0x13,
        CreateHsf_JsonHashFailure = 0x14,

        DecodeHsf_AsnDecodeFailure = 0x20,
        DecodeHsf_OidMismatchFailure = 0x21,
        DecodeHsf_CreateJsonDigestFailure = 0x22,
        DecodeHsf_PublicKeyAllocFailure = 0x23,
        DecodeHsf_PublicKeyImportFailure = 0x24,
        DecodeHsf_JsonParseFailure = 0x25,
        DecodeHsf_VersionMismatch = 0x26,
        DecodeHsf_ReadSerialNumberFailure = 0x27,
        DecodeHsf_ReadFrameworkEcFailure = 0x28,
        DecodeHsf_ReadMachineArrayFailure = 0x29,
        DecodeHsf_MachineArrayInvalidLength = 0x2A,
        DecodeHsf_ReadHashedAuthCodeFailure = 0x2B,
        DecodeHsf_ReadExpirationFailure = 0x2C,
        DecodeHsf_ReadRequestIdFailure = 0x2D,
        DecodeHsf_ReadSaltFailure = 0x2E,
        DecodeHsf_ReadIterationsFailure = 0x2F,

        VerifyAcf_AsnDecodeFailure = 0x30,
        VerifyAcf_OidMismatchFailure = 0x31,
        VerifyAcf_CreateJsonDigestFailure = 0x32,
        VerifyAcf_PublicKeyAllocFailure = 0x33,
        VerifyAcf_PublicKeyImportFailure = 0x34,
        VerifyAcf_InvalidParm = 0x35,
        VerifyAcf_Asn1CopyFailure = 0x36,
        VerifyAcf_Nid2OidFailed = 0x37,
        VerifyAcf_ProcessingTypeMismatch = 0x38,

        DetermineAuth_PasswordHashFailure = 0x40,
        DetermineAuth_Asn1TimeAllocFailure = 0x41,
        DetermineAuth_Asn1TimeFromUnixFailure = 0x42,
        DetermineAuth_AsnAllocFailure = 0x43,
        DetermineAuth_Asn1TimeCompareFailure = 0x44,
        DetermineAuth_GetAsn1UnixEpoch = 0x45,
        DetermineAuth_Asn1ExpirationToUnixFailure = 0x46,
        DetermineAuth_Asn1ExpirationToUnixOsslFailure = 0x47,

        Util_ValueFromJsonTagFailure = 0x50,

        HexToBin_HexPairOverflow = 0x60,
        HexToBin_InvalidHexString = 0x61,

        DateFromString_StrtoulFailure = 0x70,
        DateFromString_InvalidFormat = 0x71,
        DateFromString_InvalidParm = 0x72,

        GetAsn1Time_SetStringFailure = 0x80,
        GetAsn1Time_FormatStringFailure = 0x81,
        GetAsn1Time_InvalidParm = 0x82,

        CreatePasswordHash_InvalidInputBuffer = 0x90,
        CreatePasswordHash_InvalidInputBufferLength = 0x91,
        CreatePasswordHash_InvalidOutputBuffer = 0x92,
        CreatePasswordHash_InvalidOutputBufferLength = 0x93,
        CreatePasswordHash_OsslCallFailed = 0x94,
        CreatePasswordHash_InvalidInputSaltBuffer = 0x95,
        CreatePasswordHash_InvalidInputSaltLength = 0x96,
        CreatePasswordHash_ZeroIterations = 0x97,
        CreatePasswordHash_IterationTooLarge = 0x98,

        CreateDigest_InvalidInputBuffer = 0xA0,
        CreateDigest_InvalidInputBufferLength = 0xA1,
        CreateDigest_InvalidOutputBuffer = 0xA2,
        CreateDigest_InvalidOutputBufferLength = 0xA3,
        CreateDigest_OsslCallFailed = 0xA4,

        GetUnsignedIntFromString_InvalidBuffer = 0xB0,
        GetUnsignedIntFromString_ZeroLengthBuffer = 0xB1,
        GetUnsignedIntFromString_IntegerOverflow = 0xB2,
        GetUnsignedIntFromString_InvalidString = 0xB3,

        GetAuthFromFrameworkEc_InvalidParm = 0xC0,
        GetAuthFromFrameworkEc_InvalidFrameworkEc = 0xC1,

        // Must fit in 1-byte
    };

    inline CeLoginRc(const RcBase reasonParm) :
        mComponent(Base), mReason(reasonParm)
    {}

    inline CeLoginRc(const Component componentParm, const uint8_t reasonParm) :
        mComponent(0 == reasonParm ? 0 : componentParm), mReason(reasonParm)
    {}

    operator uint16_t() const
    {
        // Format manually to allow for consistant behavior on Big vs Little
        // Endian systems
        return (uint8_t)mComponent << 8 | (uint8_t)mReason;
    }

    uint8_t mComponent;
    uint8_t mReason;
};

CeLoginRc getServiceAuthorityV1(
    const uint8_t* accessControlFileParm,
    const uint64_t accessControlFileLengthParm, const char* passwordParm,
    const uint64_t passwordLengthParm,
    const uint64_t timeSinceUnixEpocInSecondsParm, const uint8_t* publicKeyParm,
    const uint64_t publicKeyLengthParm, const char* serialNumberParm,
    const uint64_t serialNumberLengthParm, ServiceAuthority& authorityParm,
    uint64_t& expirationTimeParm);



} // namespace CeLogin



#endif
