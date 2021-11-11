#include "CeLogin.h"
#include "CeLoginAsnV1.h"
#include "CeLoginJson.h"
#include "CeLoginUtil.h"
#include "openssl/asn1.h"
#include "openssl/asn1t.h"
#include "openssl/err.h"
#include "openssl/rsa.h"
#include "openssl/x509.h"
#include <map>
#include <getopt.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include <chrono>
#include <ctime>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <variant>
#include <vector>

#define FAILURE -1
#define SOURCE_FILE_VERSION 1
#define UNSET_SERIAL_NUM_KEYWORD "UNSET"

//RUN_UNIT_TESTS should only be enabled when running
//meson unit tests, otherwise this shoudn't be enabled
#ifdef RUN_UNIT_TESTS
#include "testconf.h"
// print logs to stdout under test
#define pam_syslog(X, Y, ...) printf(__VA_ARGS__)
#else
#include <sdbusplus/bus.hpp>
#define ACF_FILE_PATH "/etc/acf/service.acf"
#define PROD_PUB_KEY_FILE_PATH "/srv/ibm-acf/ibmacf-prod.key"
#define PROD_BACKUP_PUB_KEY_FILE_PATH "/srv/ibm-acf/ibmacf-prod-backup.key"
#define DEV_PUB_KEY_FILE_PATH "/srv/ibm-acf/ibmacf-dev.key"
#endif

// DBUS definitions for getting host's serial number property
#define DBUS_INVENTORY_SYSTEM_OBJECT "/xyz/openbmc_project/inventory/system"
#define DBUS_INVENTORY_ASSET_INTERFACE                                         \
    "xyz.openbmc_project.Inventory.Decorator.Asset"
#define DBUS_SERIAL_NUM_PROP "SerialNumber"

#define DBUS_SOFTWARE_OBJECT "/xyz/openbmc_project/software"
#define DBUS_FIELDMODE_INTERFACE "xyz.openbmc_project.Control.FieldMode"
#define DBUS_FIELD_MODE_PROP "FieldModeEnabled"

const char* default_user = "service";

using namespace std;
using namespace CeLogin;

// mapping of failure codes to messages
std::map<int, std::string> mapping = {
    {0x00, "Success"},
    {0x01, "Failure"},
    {0x02, "UnsupportedVersion"},
    {0x03, "SignatureNotValid"},
    {0x04, "PasswordNotValid"},
    {0x05, "AcfExpired"},
    {0x06, "SerialNumberMismatch"},
    {0x07, "JsonDataAllocationFailure"},

    {0x13, "CreateHsf_PasswordHashFailure"},
    {0x14, "CreateHsf_JsonHashFailure"},

    {0x20, "DecodeHsf_AsnDecodeFailure"},
    {0x21, "DecodeHsf_OidMismatchFailure"},
    {0x22, "DecodeHsf_CreateJsonDigestFailure"},
    {0x23, "DecodeHsf_PublicKeyAllocFailure"},
    {0x24, "DecodeHsf_PublicKeyImportFailure"},
    {0x25, "DecodeHsf_JsonParseFailure"},
    {0x26, "DecodeHsf_VersionMismatch"},
    {0x27, "DecodeHsf_ReadSerialNumberFailure"},
    {0x28, "DecodeHsf_ReadFrameworkEcFailure"},
    {0x29, "DecodeHsf_ReadMachineArrayFailure"},
    {0x2A, "DecodeHsf_MachineArrayInvalidLength"},
    {0x2B, "DecodeHsf_ReadHashedAuthCodeFailure"},
    {0x2C, "DecodeHsf_ReadExpirationFailure"},
    {0x2D, "DecodeHsf_ReadRequestIdFailure"},

    {0x30, "VerifyAcf_AsnDecodeFailure"},
    {0x31, "VerifyAcf_OidMismatchFailure"},
    {0x32, "VerifyAcf_CreateJsonDigestFailure"},
    {0x33, "VerifyAcf_PublicKeyAllocFailure"},
    {0x34, "VerifyAcf_PublicKeyImportFailure"},
    {0x35, "VerifyAcf_InvalidParm"},
    {0x36, "VerifyAcf_Asn1CopyFailure"},
    {0x37, "VerifyAcf_Nid2OidFailed"},
    {0x38, "VerifyAcf_ProcessingTypeMismatch"},

    {0x40, "DetermineAuth_PasswordHashFailure"},
    {0x41, "DetermineAuth_Asn1TimeAllocFailure"},
    {0x42, "DetermineAuth_Asn1TimeFromUnixFailure"},
    {0x43, "DetermineAuth_AsnAllocFailure"},
    {0x44, "DetermineAuth_Asn1TimeCompareFailure"},

    {0x50, "Util_ValueFromJsonTagFailure"},

    {0x60, "HexToBin_HexPairOverflow"},
    {0x61, "HexToBin_InvalidHexString"},

    {0x70, "DateFromString_StrtoulFailure"},
    {0x71, "DateFromString_InvalidFormat"},
    {0x72, "DateFromString_InvalidParm"},

    {0x80, "GetAsn1Time_SetStringFailure"},
    {0x81, "GetAsn1Time_FormatStringFailure"},
    {0x82, "GetAsn1Time_InvalidParm"},

    {0x90, "CreatePasswordHash_InvalidInputBuffer"},
    {0x91, "CreatePasswordHash_InvalidInputBufferLength"},
    {0x92, "CreatePasswordHash_InvalidOutputBuffer"},
    {0x93, "CreatePasswordHash_InvalidOutputBufferLength"},
    {0x94, "CreatePasswordHash_OsslCallFailed"},

    {0xA0, "CreateDigest_InvalidInputBuffer"},
    {0xA1, "CreateDigest_InvalidInputBufferLength"},
    {0xA2, "CreateDigest_InvalidOutputBuffer"},
    {0xA3, "CreateDigest_InvalidOutputBufferLength"},
    {0xA4, "CreateDigest_OsslCallFailed"},

    {0xB0, "GetUnsignedIntFromString_InvalidBuffer"},
    {0xB1, "GetUnsignedIntFromString_ZeroLengthBuffer"},
    {0xB2, "GetUnsignedIntFromString_IntegerOverflow"},
    {0xB3, "GetUnsignedIntFromString_InvalidString"},

    {0xC0, "GetAuthFromFrameworkEc_InvalidParm"},
};
// Determine the user name of the auth attempt.
// Returns:
//    PAM_SUCCESS for the special service user.
//    {any retcode} if pam_get_user failed.
//    PAM_IGNORE otherwise.
int ignore_other_accounts(pam_handle_t* pamh, const char* user_parm)
{
    const char* login_user = NULL;
    int retval = pam_get_user(pamh, &login_user, NULL);
    if (retval != PAM_SUCCESS)
    {
        pam_syslog(pamh, LOG_NOTICE, "Unable to get user name: %s\n",
                   pam_strerror(pamh, retval));
        return retval;
    }
    if (0 != strcmp(user_parm, login_user))
    {
        return PAM_IGNORE;
    }
    return PAM_SUCCESS;
}

bool readBinaryFile(const std::string fileNameParm,
                    std::vector<uint8_t>& bufferParm, pam_handle_t* pamh)
{
    std::ifstream sInputFile;
    if (!fileNameParm.empty())
    {
        sInputFile.open(fileNameParm.c_str(), std::ios::in | std::ios::binary);
        if (sInputFile.is_open())
        {
            // Get the size of the file
            sInputFile.seekg(0, std::ios::end);
            std::streampos size = sInputFile.tellg();
            sInputFile.seekg(0, std::ios::beg);

            bufferParm.reserve(size);
            bufferParm.assign(size, 0);

            sInputFile.read((char*)bufferParm.data(), size);
            sInputFile.close();

            return true;
        }
        else
        {
            pam_syslog(pamh, LOG_WARNING, "Failed to open file %s\n",
                       fileNameParm.c_str());
        }
    }
    else
    {
        pam_syslog(pamh, LOG_WARNING, "filename empty");
    }

    return false;
}

int verifyACF(string acfPubKeypath, const char* passwordParm, string mSerialNumber,
              pam_handle_t* pamh)
{
    string acfFileName = (ACF_FILE_PATH);
    vector<uint8_t> sAcf;
    time_t sTime = time(NULL);
    const uint64_t passwordLengthParm = strlen(passwordParm);
    const uint64_t timeSinceUnixEpocInSecondsParm = sTime;
    vector<uint8_t> sPublicKey;
    const char* serialNumberParm = mSerialNumber.data();
    const uint64_t serialNumberLengthParm = mSerialNumber.size();
    CeLogin::ServiceAuthority sAuth = CeLogin::ServiceAuth_None;

    uint64_t sExpiration = 0;
    if (readBinaryFile(acfFileName, sAcf, pamh))
    {
        if (readBinaryFile(acfPubKeypath, sPublicKey, pamh))
        {
            const uint8_t* publicKeyParm = (const uint8_t*)sPublicKey.data();
            const uint64_t publicKeyLengthParm = sPublicKey.size();

            const uint8_t* accessControlFileParm = sAcf.data();
            const uint64_t accessControlFileLengthParm = sAcf.size();

            CeLogin::CeLoginRc sRc = CeLogin::getServiceAuthorityV1(
                accessControlFileParm, accessControlFileLengthParm,
                passwordParm, passwordLengthParm,
                timeSinceUnixEpocInSecondsParm, publicKeyParm,
                publicKeyLengthParm, serialNumberParm, serialNumberLengthParm,
                sAuth, sExpiration);
            if (CeLoginRc::Success == sRc)
            {
                return PAM_SUCCESS;
            }
            else
            {
                pam_syslog(pamh, LOG_WARNING, "Error number: 0x%X\n",
                           (int)sRc.mReason);
                pam_syslog(pamh, LOG_WARNING, "Error message: %s\n",
                           (mapping.at((int)sRc.mReason)).c_str());
                return PAM_AUTH_ERR;
            }
        }
        else
        {
            pam_syslog(pamh, LOG_WARNING, "failed reading public key.\n");
            return PAM_SYSTEM_ERR;
        }
    }
    else
    {
        pam_syslog(pamh, LOG_WARNING, "failed reading ACF.\n");
        return PAM_SYSTEM_ERR;
    }
    return PAM_SUCCESS;
}
#ifdef RUN_UNIT_TESTS
int fieldModeEnabled = 1;
string mSerialNumber = "UNSET";
//manually set variables (fieldModeEnabled and mSerialNumber)
//for googletest for as dbus objects
//aren't available on non OpenBMC targets
void setFieldModeProperty(int fieldModeEnabledParam)
{
    fieldModeEnabled = fieldModeEnabledParam;
}

void setSerialNumberProperty(const string& obj){
    mSerialNumber = obj;
}
#else
int readFieldModeProperty(const string& obj, const string& inf,
                          const string& prop, pam_handle_t* pamh)
{
    bool propBool = false;
    std::string object = obj;
    auto bus = sdbusplus::bus::new_default();
    auto properties = bus.new_method_call(
        "xyz.openbmc_project.Software.BMC.Updater", object.c_str(),
        "org.freedesktop.DBus.Properties", "Get");
    properties.append(inf);
    properties.append(prop);
    try
    {
        auto result = bus.call(properties);
        if (!result.is_method_error())
        {
            std::variant<bool> val{false};
            result.read(val);
            if (auto pVal = std::get_if<bool>(&val))
            {
                pam_syslog(pamh, LOG_DEBUG, "FieldModeProperty = %d\n", (*pVal));
                propBool = (*pVal);
            }
        }
    }
    catch (const std::exception& exc)
    {
        pam_syslog(pamh, LOG_ERR, "dbus call failure: %s\n", exc.what());
        return FAILURE;
    }

    return (int)propBool;
}

string readMachineSerialNumberProperty(const string& obj, const string& inf,
                                       const string& prop, pam_handle_t* pamh)
{
    std::string propSerialNum = "";
    std::string object = obj;
    auto bus = sdbusplus::bus::new_default();
    auto properties = bus.new_method_call(
        "xyz.openbmc_project.Inventory.Manager", object.c_str(),
        "org.freedesktop.DBus.Properties", "Get");
    properties.append(inf);
    properties.append(prop);
    try
    {
        auto result = bus.call(properties);
        if (!result.is_method_error())
        {
            std::variant<string> val;
            result.read(val);
            if (auto pVal = std::get_if<string>(&val))
            {
                propSerialNum.assign((pVal->data()), pVal->size());
            }
            else
            {
                pam_syslog(pamh, LOG_ERR,
                           "could not get the host's serial number\n");
            }
        }
    }
    catch (const std::exception& exc)
    {
        pam_syslog(pamh, LOG_ERR,
                   "dbus call for getting serial number failured: %s\n",
                   exc.what());
        propSerialNum = "";
    }
    return propSerialNum;
}
#endif

PAM_EXTERN int pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc,
                                   const char** argv)
{
#ifdef HAVE_PAM_FAIL_DELAY
    pam_fail_delay(pamh, 2'000'000);
#endif // HAVE_PAM_FAIL_DELAY

    const char* username = NULL;
    // Only handle the service user.
    int retval = -1;
    retval = pam_get_user(pamh, &username, NULL);
    if (retval != PAM_SUCCESS)
    {
        return retval;
    }
    else if (strcmp(default_user, username))
    {
        return PAM_IGNORE;
    }

    // Get the user's password
    const char* password;
    retval = pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);

    if (retval != PAM_SUCCESS)
    {
        pam_syslog(pamh, LOG_WARNING, "Unable to get password\n");
        return PAM_AUTH_ERR;
    }

    const char* user_parm = default_user;
    string acfDevPubKeypath = (DEV_PUB_KEY_FILE_PATH);
    string acfProdPubKeypath = (PROD_PUB_KEY_FILE_PATH);
    string acfProdBackupPubKeypath = (PROD_BACKUP_PUB_KEY_FILE_PATH);
    pam_syslog(pamh, LOG_INFO, "Performing ACF auth for the %s user.\n",
               user_parm);

    // Get host's serial number
#ifndef RUN_UNIT_TESTS
    string mSerialNumber = readMachineSerialNumberProperty(
        DBUS_INVENTORY_SYSTEM_OBJECT, DBUS_INVENTORY_ASSET_INTERFACE,
        DBUS_SERIAL_NUM_PROP, pamh);
#endif
    // If serial number is empty on machine set as UNSET for check with acf
    if (mSerialNumber.empty())
    {
        mSerialNumber = UNSET_SERIAL_NUM_KEYWORD;
    }
    pam_syslog(pamh, LOG_INFO, "Host Serial Number = %s\n",
               mSerialNumber.c_str());

    int verifyRc = PAM_AUTH_ERR;

    // Assume this is a production key then check for development if not prod
    // key
    verifyRc = verifyACF(acfProdPubKeypath, password, mSerialNumber, pamh);

    if (verifyRc == PAM_SUCCESS)
    {
        pam_syslog(pamh, LOG_INFO,
                   "Production ACF authentication completed successfully\n");
        return PAM_SUCCESS;
    }

    verifyRc = verifyACF(acfProdBackupPubKeypath, password, mSerialNumber, pamh);

    if (verifyRc == PAM_SUCCESS)
    {
        pam_syslog(pamh, LOG_INFO,
                   "Production Backup ACF authentication completed successfully\n");
        return PAM_SUCCESS;
    }

    // Only check for development key if BMC is not in field mode
#ifndef RUN_UNIT_TESTS
    int fieldModeEnabled = readFieldModeProperty(
        DBUS_SOFTWARE_OBJECT, DBUS_FIELDMODE_INTERFACE,
        DBUS_FIELD_MODE_PROP, pamh);
#endif
    if (fieldModeEnabled == FAILURE)
    {
        pam_syslog(pamh, LOG_ERR,
                   "Could not get field mode enabled property\n");
        return PAM_SYSTEM_ERR;
    }

    if (fieldModeEnabled == 0)
    {
        verifyRc =
            verifyACF(acfDevPubKeypath, password, mSerialNumber, pamh);
        if (verifyRc == PAM_SUCCESS)
        {
            pam_syslog(
                pamh, LOG_INFO,
                "Development ACF authentication completed successfully\n");
            return PAM_SUCCESS;
        }
    }
    return verifyRc;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t* pamh, int flags, int argc,
                              const char** argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t* pamh, int flags, int argc,
                                const char** argv)
{
    // Only handle the service user.
    const char* user_parm = default_user;
    int retval = ignore_other_accounts(pamh, user_parm);
    if (retval == PAM_IGNORE)
    {
        retval = PAM_PERM_DENIED;
    }
    return retval;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t* pamh, int flags, int argc,
                                   const char** argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t* pamh, int flags, int argc,
                                    const char** argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t* pamh, int flags, int argc,
                                const char** argv)
{
    // Only handle the service user.  Reject all password changes.
    const char* user_parm = default_user;
    int retval = ignore_other_accounts(pamh, user_parm);
    switch(retval) {
        case PAM_SUCCESS:
            retval = PAM_AUTHTOK_ERR;
            break;

        case PAM_IGNORE:
            retval = PAM_SUCCESS;
            break;
    }

    return retval;
}
