#include "DataTypes.h"

/**
* Convert entry type value to enum.
* Returns BITLOCKER_METADATA_ENTRY_TYPE::UNKNOWN if unknown or invalid.
*/
BITLOCKER_METADATA_ENTRY_TYPE getMetadataEntryTypeEnum(uint16_t val) {
    switch (val) {
    case 0:
        return BITLOCKER_METADATA_ENTRY_TYPE::PROPERTY;
    case 2:
        return BITLOCKER_METADATA_ENTRY_TYPE::VOLUME_MASTER_KEY;
    case 3:
        return BITLOCKER_METADATA_ENTRY_TYPE::FULL_VOLUME_ENCRYPTION_KEY;
    case 4:
        return BITLOCKER_METADATA_ENTRY_TYPE::VALIDATION;
    case 6:
        return BITLOCKER_METADATA_ENTRY_TYPE::STARTUP_KEY;
    case 7:
        return BITLOCKER_METADATA_ENTRY_TYPE::DESCRIPTION;
    case 0xf:
        return BITLOCKER_METADATA_ENTRY_TYPE::VOLUME_HEADER_BLOCK;
    default:
        return BITLOCKER_METADATA_ENTRY_TYPE::UNKNOWN;
    }
}

string convertMetadataEntryTypeToString(BITLOCKER_METADATA_ENTRY_TYPE type) {
    switch (type) {
    case BITLOCKER_METADATA_ENTRY_TYPE::PROPERTY:
        return "Property";
    case BITLOCKER_METADATA_ENTRY_TYPE::VOLUME_MASTER_KEY:
        return "Volume Master Key";
    case BITLOCKER_METADATA_ENTRY_TYPE::FULL_VOLUME_ENCRYPTION_KEY:
        return "Full Volume Encryption Key";
    case BITLOCKER_METADATA_ENTRY_TYPE::VALIDATION:
        return "Validation";
    case BITLOCKER_METADATA_ENTRY_TYPE::STARTUP_KEY:
        return "Startup Key";
    case BITLOCKER_METADATA_ENTRY_TYPE::DESCRIPTION:
        return "Description";
    case BITLOCKER_METADATA_ENTRY_TYPE::VOLUME_HEADER_BLOCK:
        return "Volume Header Block";
    case BITLOCKER_METADATA_ENTRY_TYPE::UNKNOWN:
    default:
        return "Unknown";
    }
}

/**
* Convert value type value to enum.
* Returns BITLOCKER_METADATA_VALUE_TYPE::UNKNOWN if invalid.
*/
BITLOCKER_METADATA_VALUE_TYPE getMetadataValueTypeEnum(uint16_t val) {
    switch (val) {
    case 0:
        return BITLOCKER_METADATA_VALUE_TYPE::ERASED;
    case 1:
        return BITLOCKER_METADATA_VALUE_TYPE::KEY;
    case 2:
        return BITLOCKER_METADATA_VALUE_TYPE::UNICODE_STRING;
    case 3:
        return BITLOCKER_METADATA_VALUE_TYPE::STRETCH_KEY;
    case 4:
        return BITLOCKER_METADATA_VALUE_TYPE::USE_KEY;
    case 5:
        return BITLOCKER_METADATA_VALUE_TYPE::AES_CCM_ENCRYPTED_KEY;
    case 6:
        return BITLOCKER_METADATA_VALUE_TYPE::TPM_ENCODED_KEY;
    case 7:
        return BITLOCKER_METADATA_VALUE_TYPE::VALIDATION;
    case 8:
        return BITLOCKER_METADATA_VALUE_TYPE::VOLUME_MASTER_KEY;
    case 9:
        return BITLOCKER_METADATA_VALUE_TYPE::EXTERNAL_KEY;
    case 0xa:
        return BITLOCKER_METADATA_VALUE_TYPE::UPDATE;
    case 0xb:
        return BITLOCKER_METADATA_VALUE_TYPE::ERROR_VAL;
    case 0xf:
        return BITLOCKER_METADATA_VALUE_TYPE::OFFSET_AND_SIZE;
    default:
        return BITLOCKER_METADATA_VALUE_TYPE::UNKNOWN;
    }
}

string convertMetadataValueTypeToString(BITLOCKER_METADATA_VALUE_TYPE type) {
    switch (type) {
    case BITLOCKER_METADATA_VALUE_TYPE::ERASED:
        return "Erased";
    case BITLOCKER_METADATA_VALUE_TYPE::KEY:
        return "Key";
    case BITLOCKER_METADATA_VALUE_TYPE::UNICODE_STRING:
        return "Unicode String";
    case BITLOCKER_METADATA_VALUE_TYPE::STRETCH_KEY:
        return "Stretch Key";
    case BITLOCKER_METADATA_VALUE_TYPE::USE_KEY:
        return "Use Key";
    case BITLOCKER_METADATA_VALUE_TYPE::AES_CCM_ENCRYPTED_KEY:
        return "AES-CCM Encrypted Key";
    case BITLOCKER_METADATA_VALUE_TYPE::TPM_ENCODED_KEY:
        return "TPM Encoded Key";
    case BITLOCKER_METADATA_VALUE_TYPE::VALIDATION:
        return "Validation";
    case BITLOCKER_METADATA_VALUE_TYPE::VOLUME_MASTER_KEY:
        return "Volume Master Key";
    case BITLOCKER_METADATA_VALUE_TYPE::EXTERNAL_KEY:
        return "External Key";
    case BITLOCKER_METADATA_VALUE_TYPE::UPDATE:
        return "Update";
    case BITLOCKER_METADATA_VALUE_TYPE::ERROR_VAL:
        return "Error";
    case BITLOCKER_METADATA_VALUE_TYPE::OFFSET_AND_SIZE:
        return "Offset and Size";
    case BITLOCKER_METADATA_VALUE_TYPE::UNKNOWN:
    default:
        return "Unknown";
    }
}

BITLOCKER_KEY_PROTECTION_TYPE getKeyProtectionTypeEnum(uint16_t val) {
    switch (val) {
    case 0x0000:
        return BITLOCKER_KEY_PROTECTION_TYPE::CLEAR_KEY;
    case 0x0100:
        return BITLOCKER_KEY_PROTECTION_TYPE::TPM;
    case 0x0200:
        return BITLOCKER_KEY_PROTECTION_TYPE::STARTUP_KEY;
    case 0x0500:
        return BITLOCKER_KEY_PROTECTION_TYPE::TPM_AND_PIN;
    case 0x0800:
        return BITLOCKER_KEY_PROTECTION_TYPE::RECOVERY_PASSWORD;
    case 0x2000:
        return BITLOCKER_KEY_PROTECTION_TYPE::PASSWORD;
    default:
        return BITLOCKER_KEY_PROTECTION_TYPE::UNKNOWN;
    }
}

string convertKeyProtectionTypeToString(BITLOCKER_KEY_PROTECTION_TYPE type) {
    switch (type) {
    case BITLOCKER_KEY_PROTECTION_TYPE::CLEAR_KEY:
        return "Clear Key";
    case BITLOCKER_KEY_PROTECTION_TYPE::TPM:
        return "TPM";
    case BITLOCKER_KEY_PROTECTION_TYPE::STARTUP_KEY:
        return "Startup Key";
    case BITLOCKER_KEY_PROTECTION_TYPE::TPM_AND_PIN:
        return "TPM and PIN";
    case BITLOCKER_KEY_PROTECTION_TYPE::RECOVERY_PASSWORD:
        return "Recovery Password";
    case BITLOCKER_KEY_PROTECTION_TYPE::PASSWORD:
        return "Password";
    case BITLOCKER_KEY_PROTECTION_TYPE::UNKNOWN:
    default:
        return "Unknown";
    }
}

BITLOCKER_ENCRYPTION_TYPE getEncryptionTypeEnum(uint16_t val) {
    switch (val) {
    case 0x1000:
        return BITLOCKER_ENCRYPTION_TYPE::STRETCH_KEY;
    case 0x2000:
    case 0x2001:
    case 0x2004:
        return BITLOCKER_ENCRYPTION_TYPE::AES_CCM_256;
    case 0x2002:
        return BITLOCKER_ENCRYPTION_TYPE::EXTERN_KEY;
    case 0x2003:
        return BITLOCKER_ENCRYPTION_TYPE::VMK;
    case 0x2005:
        return BITLOCKER_ENCRYPTION_TYPE::HASH_256;
    case 0x8000:
        return BITLOCKER_ENCRYPTION_TYPE::AES_CBC_128_DIFF;
    case 0x8001:
        return BITLOCKER_ENCRYPTION_TYPE::AES_CBC_256_DIFF;
    case 0x8002:
        return BITLOCKER_ENCRYPTION_TYPE::AES_CBC_128;
    case 0x8003:
        return BITLOCKER_ENCRYPTION_TYPE::AES_CBC_256;
    case 0x8004:
        return BITLOCKER_ENCRYPTION_TYPE::AES_XTS_128;
    case 0x8005:
        return BITLOCKER_ENCRYPTION_TYPE::AES_XTS_256;
    default:
        return BITLOCKER_ENCRYPTION_TYPE::UNKNOWN;
    }
}

string convertEncryptionTypeToString(BITLOCKER_ENCRYPTION_TYPE type) {
    switch (type) {
    case BITLOCKER_ENCRYPTION_TYPE::STRETCH_KEY:
        return "Stretch Key";
    case BITLOCKER_ENCRYPTION_TYPE::AES_CCM_256:
        return "AES-CCM 256";
    case BITLOCKER_ENCRYPTION_TYPE::EXTERN_KEY:
        return "Extern Key";
    case BITLOCKER_ENCRYPTION_TYPE::VMK:
        return "VMK";
    case BITLOCKER_ENCRYPTION_TYPE::HASH_256:
        return "Hash 256";
    case BITLOCKER_ENCRYPTION_TYPE::AES_CBC_128_DIFF:
        return "AES CBC 128-bit with diffuser";
    case BITLOCKER_ENCRYPTION_TYPE::AES_CBC_256_DIFF:
        return "AES CBC 256-bit with diffuser";
    case BITLOCKER_ENCRYPTION_TYPE::AES_CBC_128:
        return "AES CBC 128-bit";
    case BITLOCKER_ENCRYPTION_TYPE::AES_CBC_256:
        return "AES CBC 256-bit";
    case BITLOCKER_ENCRYPTION_TYPE::AES_XTS_128:
        return "AES-XTS 128-bit";
    case BITLOCKER_ENCRYPTION_TYPE::AES_XTS_256:
        return "AES-XTS 256-bit";
    default:
        return "Unknown";
    }
}

bool isAESCBC(BITLOCKER_ENCRYPTION_TYPE type) {
    return (type == BITLOCKER_ENCRYPTION_TYPE::AES_CBC_128_DIFF
        || type == BITLOCKER_ENCRYPTION_TYPE::AES_CBC_256_DIFF
        || type == BITLOCKER_ENCRYPTION_TYPE::AES_CBC_128
        || type == BITLOCKER_ENCRYPTION_TYPE::AES_CBC_256);
}

bool isAESXTS(BITLOCKER_ENCRYPTION_TYPE type) {
    return (type == BITLOCKER_ENCRYPTION_TYPE::AES_XTS_128
        || type == BITLOCKER_ENCRYPTION_TYPE::AES_XTS_256);
}

bool usesDiffuser(BITLOCKER_ENCRYPTION_TYPE type) {
    return (type == BITLOCKER_ENCRYPTION_TYPE::AES_CBC_128_DIFF
        || type == BITLOCKER_ENCRYPTION_TYPE::AES_CBC_256_DIFF);
}