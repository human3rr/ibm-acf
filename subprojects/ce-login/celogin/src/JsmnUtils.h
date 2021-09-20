
#include <stdint.h>

#define JSMN_HEADER
#include <jsmn.h>
#undef JSMN_HEADER

#ifndef _JSMNUTILS_H
#define _JSMNUTILS_H

namespace JsmnUtils
{
enum JsmnUtilRc
{
    Success = 0,
    Failure = 1,

    GetNextJsonEntry_InvalidParm = 10,
    GetNextJsonEntry_BadWalk = 11,

    ObjectGetValueByKey_InvalidParm = 20,
    ObjectGetValueByKey_KeyNotFound = 21,
    ObjectGetValueByKey_DuplicateKeyFound = 22,
    ObjectGetValueByKey_ObjectMissingValue = 23,
};

struct JsmnString
{
    const char* mCharArray; // Is NOT null terminated
    uint64_t mCharLength;
};

struct JsmnState
{
    const char* mJsonString;
    uint64_t mJsonStringLength;
    const jsmntok_t* mTokenArray;
    uint64_t mTokenArrayLength;

    inline bool isValid() const
    {
        return mJsonString && mJsonStringLength > 0 && mTokenArray &&
               mTokenArrayLength > 0;
    }

    inline const jsmntok_t& getToken(const uint64_t sIdx) const
    {
        return mTokenArray[sIdx];
    }

    inline bool isTokenIdxValid(const uint64_t tokenIdxParm) const
    {
        return (tokenIdxParm < mTokenArrayLength);
    }

    inline JsmnString getString(const uint64_t tokenIdxParm) const
    {
        const jsmntok_t& sToken = getToken(tokenIdxParm);
        const int sStringOffset = sToken.start;
        const int sStringLength = sToken.end - sStringOffset;
        const char* sString = mJsonString + sStringOffset;

        JsmnString sJsmnString;
        sJsmnString.mCharArray = sString;
        sJsmnString.mCharLength = sStringLength;
        return sJsmnString;
    }
};

JsmnUtilRc GetNextJsonEntry(const JsmnState& jsmnState,
                            const uint64_t currentIdxParm,
                            uint64_t& nextIdxParm);

void PrintJsmnToken(const JsmnState& jsmnState, const uint64_t tokenIdxParm);

JsmnUtilRc ObjectGetValueByKey(const JsmnState& jsmnStateParm,
                               const uint64_t objectRootIdxParm,
                               const char* keyParm, const uint64_t keyLenParm,
                               uint64_t& valueIdxParm);

bool SafeJsmnStringCompare(const JsmnString& jsmnStringParm,
                           const char* stringParm,
                           const uint64_t stringLengthParm);

}; // namespace JsmnUtils

#endif
