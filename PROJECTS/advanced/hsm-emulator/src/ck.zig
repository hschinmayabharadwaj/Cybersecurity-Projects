// ©AngelaMos | 2026
// ck.zig

pub const CK_BYTE = u8;
pub const CK_CHAR = u8;
pub const CK_UTF8CHAR = u8;
pub const CK_BBOOL = u8;
pub const CK_ULONG = c_ulong;
pub const CK_LONG = c_long;
pub const CK_FLAGS = CK_ULONG;
pub const CK_RV = CK_ULONG;
pub const CK_SLOT_ID = CK_ULONG;
pub const CK_SESSION_HANDLE = CK_ULONG;
pub const CK_OBJECT_HANDLE = CK_ULONG;
pub const CK_OBJECT_CLASS = CK_ULONG;
pub const CK_KEY_TYPE = CK_ULONG;
pub const CK_MECHANISM_TYPE = CK_ULONG;
pub const CK_ATTRIBUTE_TYPE = CK_ULONG;
pub const CK_RSA_PKCS_MGF_TYPE = CK_ULONG;
pub const CK_RSA_PKCS_OAEP_SOURCE_TYPE = CK_ULONG;
pub const CK_USER_TYPE = CK_ULONG;
pub const CK_STATE = CK_ULONG;
pub const CK_NOTIFICATION = CK_ULONG;

pub const CK_TRUE: CK_BBOOL = 1;
pub const CK_FALSE: CK_BBOOL = 0;
pub const CK_INVALID_HANDLE: CK_ULONG = 0;
pub const CK_UNAVAILABLE_INFORMATION: CK_ULONG = ~@as(CK_ULONG, 0);
pub const CK_EFFECTIVELY_INFINITE: CK_ULONG = 0;

pub const CKR_OK: CK_RV = 0x00000000;
pub const CKR_CANCEL: CK_RV = 0x00000001;
pub const CKR_HOST_MEMORY: CK_RV = 0x00000002;
pub const CKR_SLOT_ID_INVALID: CK_RV = 0x00000003;
pub const CKR_GENERAL_ERROR: CK_RV = 0x00000005;
pub const CKR_FUNCTION_FAILED: CK_RV = 0x00000006;
pub const CKR_ARGUMENTS_BAD: CK_RV = 0x00000007;
pub const CKR_NO_EVENT: CK_RV = 0x00000008;
pub const CKR_NEED_TO_CREATE_THREADS: CK_RV = 0x00000009;
pub const CKR_CANT_LOCK: CK_RV = 0x0000000A;
pub const CKR_ATTRIBUTE_READ_ONLY: CK_RV = 0x00000010;
pub const CKR_ATTRIBUTE_SENSITIVE: CK_RV = 0x00000011;
pub const CKR_ATTRIBUTE_TYPE_INVALID: CK_RV = 0x00000012;
pub const CKR_ATTRIBUTE_VALUE_INVALID: CK_RV = 0x00000013;
pub const CKR_ACTION_PROHIBITED: CK_RV = 0x0000001B;
pub const CKR_DATA_INVALID: CK_RV = 0x00000020;
pub const CKR_DATA_LEN_RANGE: CK_RV = 0x00000021;
pub const CKR_DEVICE_ERROR: CK_RV = 0x00000030;
pub const CKR_DEVICE_MEMORY: CK_RV = 0x00000031;
pub const CKR_DEVICE_REMOVED: CK_RV = 0x00000032;
pub const CKR_ENCRYPTED_DATA_INVALID: CK_RV = 0x00000040;
pub const CKR_ENCRYPTED_DATA_LEN_RANGE: CK_RV = 0x00000041;
pub const CKR_FUNCTION_CANCELED: CK_RV = 0x00000050;
pub const CKR_FUNCTION_NOT_PARALLEL: CK_RV = 0x00000051;
pub const CKR_FUNCTION_NOT_SUPPORTED: CK_RV = 0x00000054;
pub const CKR_KEY_HANDLE_INVALID: CK_RV = 0x00000060;
pub const CKR_KEY_SIZE_RANGE: CK_RV = 0x00000062;
pub const CKR_KEY_TYPE_INCONSISTENT: CK_RV = 0x00000063;
pub const CKR_KEY_NOT_NEEDED: CK_RV = 0x00000064;
pub const CKR_KEY_INDIGESTIBLE: CK_RV = 0x00000067;
pub const CKR_KEY_FUNCTION_NOT_PERMITTED: CK_RV = 0x00000068;
pub const CKR_KEY_NOT_WRAPPABLE: CK_RV = 0x00000069;
pub const CKR_KEY_UNEXTRACTABLE: CK_RV = 0x0000006A;
pub const CKR_MECHANISM_INVALID: CK_RV = 0x00000070;
pub const CKR_MECHANISM_PARAM_INVALID: CK_RV = 0x00000071;
pub const CKR_OBJECT_HANDLE_INVALID: CK_RV = 0x00000082;
pub const CKR_OPERATION_ACTIVE: CK_RV = 0x00000090;
pub const CKR_OPERATION_NOT_INITIALIZED: CK_RV = 0x00000091;
pub const CKR_PIN_INCORRECT: CK_RV = 0x000000A0;
pub const CKR_PIN_INVALID: CK_RV = 0x000000A1;
pub const CKR_PIN_LEN_RANGE: CK_RV = 0x000000A2;
pub const CKR_PIN_EXPIRED: CK_RV = 0x000000A3;
pub const CKR_PIN_LOCKED: CK_RV = 0x000000A4;
pub const CKR_SESSION_CLOSED: CK_RV = 0x000000B0;
pub const CKR_SESSION_COUNT: CK_RV = 0x000000B1;
pub const CKR_SESSION_HANDLE_INVALID: CK_RV = 0x000000B3;
pub const CKR_SESSION_PARALLEL_NOT_SUPPORTED: CK_RV = 0x000000B4;
pub const CKR_SESSION_READ_ONLY: CK_RV = 0x000000B5;
pub const CKR_SESSION_EXISTS: CK_RV = 0x000000B6;
pub const CKR_SESSION_READ_ONLY_EXISTS: CK_RV = 0x000000B7;
pub const CKR_SESSION_READ_WRITE_SO_EXISTS: CK_RV = 0x000000B8;
pub const CKR_SIGNATURE_INVALID: CK_RV = 0x000000C0;
pub const CKR_SIGNATURE_LEN_RANGE: CK_RV = 0x000000C1;
pub const CKR_TEMPLATE_INCOMPLETE: CK_RV = 0x000000D0;
pub const CKR_TEMPLATE_INCONSISTENT: CK_RV = 0x000000D1;
pub const CKR_TOKEN_NOT_PRESENT: CK_RV = 0x000000E0;
pub const CKR_TOKEN_NOT_RECOGNIZED: CK_RV = 0x000000E1;
pub const CKR_TOKEN_WRITE_PROTECTED: CK_RV = 0x000000E2;
pub const CKR_UNWRAPPING_KEY_HANDLE_INVALID: CK_RV = 0x000000F0;
pub const CKR_UNWRAPPING_KEY_SIZE_RANGE: CK_RV = 0x000000F1;
pub const CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: CK_RV = 0x000000F2;
pub const CKR_USER_ALREADY_LOGGED_IN: CK_RV = 0x00000100;
pub const CKR_USER_NOT_LOGGED_IN: CK_RV = 0x00000101;
pub const CKR_USER_PIN_NOT_INITIALIZED: CK_RV = 0x00000102;
pub const CKR_USER_TYPE_INVALID: CK_RV = 0x00000103;
pub const CKR_USER_ANOTHER_ALREADY_LOGGED_IN: CK_RV = 0x00000104;
pub const CKR_USER_TOO_MANY_TYPES: CK_RV = 0x00000105;
pub const CKR_WRAPPED_KEY_INVALID: CK_RV = 0x00000110;
pub const CKR_WRAPPED_KEY_LEN_RANGE: CK_RV = 0x00000112;
pub const CKR_WRAPPING_KEY_HANDLE_INVALID: CK_RV = 0x00000113;
pub const CKR_WRAPPING_KEY_SIZE_RANGE: CK_RV = 0x00000114;
pub const CKR_WRAPPING_KEY_TYPE_INCONSISTENT: CK_RV = 0x00000115;
pub const CKR_RANDOM_SEED_NOT_SUPPORTED: CK_RV = 0x00000120;
pub const CKR_RANDOM_NO_RNG: CK_RV = 0x00000121;
pub const CKR_DOMAIN_PARAMS_INVALID: CK_RV = 0x00000130;
pub const CKR_BUFFER_TOO_SMALL: CK_RV = 0x00000150;
pub const CKR_SAVED_STATE_INVALID: CK_RV = 0x00000160;
pub const CKR_INFORMATION_SENSITIVE: CK_RV = 0x00000170;
pub const CKR_STATE_UNSAVEABLE: CK_RV = 0x00000180;
pub const CKR_CRYPTOKI_NOT_INITIALIZED: CK_RV = 0x00000190;
pub const CKR_CRYPTOKI_ALREADY_INITIALIZED: CK_RV = 0x00000191;
pub const CKR_MUTEX_BAD: CK_RV = 0x000001A0;
pub const CKR_MUTEX_NOT_LOCKED: CK_RV = 0x000001A1;
pub const CKR_FUNCTION_REJECTED: CK_RV = 0x00000200;

pub const CKU_SO: CK_USER_TYPE = 0;
pub const CKU_USER: CK_USER_TYPE = 1;
pub const CKU_CONTEXT_SPECIFIC: CK_USER_TYPE = 2;

pub const CKS_RO_PUBLIC_SESSION: CK_STATE = 0;
pub const CKS_RO_USER_FUNCTIONS: CK_STATE = 1;
pub const CKS_RW_PUBLIC_SESSION: CK_STATE = 2;
pub const CKS_RW_USER_FUNCTIONS: CK_STATE = 3;
pub const CKS_RW_SO_FUNCTIONS: CK_STATE = 4;

pub const CKO_DATA: CK_OBJECT_CLASS = 0x00000000;
pub const CKO_CERTIFICATE: CK_OBJECT_CLASS = 0x00000001;
pub const CKO_PUBLIC_KEY: CK_OBJECT_CLASS = 0x00000002;
pub const CKO_PRIVATE_KEY: CK_OBJECT_CLASS = 0x00000003;
pub const CKO_SECRET_KEY: CK_OBJECT_CLASS = 0x00000004;
pub const CKO_HW_FEATURE: CK_OBJECT_CLASS = 0x00000005;
pub const CKO_DOMAIN_PARAMETERS: CK_OBJECT_CLASS = 0x00000006;
pub const CKO_MECHANISM: CK_OBJECT_CLASS = 0x00000007;

pub const CKK_RSA: CK_KEY_TYPE = 0x00000000;
pub const CKK_DSA: CK_KEY_TYPE = 0x00000001;
pub const CKK_DH: CK_KEY_TYPE = 0x00000002;
pub const CKK_EC: CK_KEY_TYPE = 0x00000003;
pub const CKK_GENERIC_SECRET: CK_KEY_TYPE = 0x00000010;
pub const CKK_AES: CK_KEY_TYPE = 0x0000001F;
pub const CKK_SHA256_HMAC: CK_KEY_TYPE = 0x0000002B;
pub const CKK_SHA384_HMAC: CK_KEY_TYPE = 0x0000002C;
pub const CKK_SHA512_HMAC: CK_KEY_TYPE = 0x0000002D;

pub const CKM_RSA_PKCS_KEY_PAIR_GEN: CK_MECHANISM_TYPE = 0x00000000;
pub const CKM_RSA_PKCS: CK_MECHANISM_TYPE = 0x00000001;
pub const CKM_RSA_PKCS_OAEP: CK_MECHANISM_TYPE = 0x00000009;
pub const CKM_RSA_PKCS_PSS: CK_MECHANISM_TYPE = 0x0000000D;
pub const CKM_SHA256_RSA_PKCS: CK_MECHANISM_TYPE = 0x00000040;
pub const CKM_SHA384_RSA_PKCS: CK_MECHANISM_TYPE = 0x00000041;
pub const CKM_SHA512_RSA_PKCS: CK_MECHANISM_TYPE = 0x00000042;
pub const CKM_SHA256_RSA_PKCS_PSS: CK_MECHANISM_TYPE = 0x00000043;
pub const CKM_SHA384_RSA_PKCS_PSS: CK_MECHANISM_TYPE = 0x00000044;
pub const CKM_SHA512_RSA_PKCS_PSS: CK_MECHANISM_TYPE = 0x00000045;
pub const CKM_SHA256: CK_MECHANISM_TYPE = 0x00000250;
pub const CKM_SHA256_HMAC: CK_MECHANISM_TYPE = 0x00000251;
pub const CKM_SHA384: CK_MECHANISM_TYPE = 0x00000260;
pub const CKM_SHA384_HMAC: CK_MECHANISM_TYPE = 0x00000261;
pub const CKM_SHA512: CK_MECHANISM_TYPE = 0x00000270;
pub const CKM_SHA512_HMAC: CK_MECHANISM_TYPE = 0x00000271;
pub const CKM_EC_KEY_PAIR_GEN: CK_MECHANISM_TYPE = 0x00001040;
pub const CKM_ECDSA: CK_MECHANISM_TYPE = 0x00001041;
pub const CKM_ECDSA_SHA256: CK_MECHANISM_TYPE = 0x00001044;
pub const CKM_ECDSA_SHA384: CK_MECHANISM_TYPE = 0x00001045;
pub const CKM_ECDSA_SHA512: CK_MECHANISM_TYPE = 0x00001046;
pub const CKM_ECDH1_DERIVE: CK_MECHANISM_TYPE = 0x00001050;
pub const CKM_AES_KEY_GEN: CK_MECHANISM_TYPE = 0x00001080;
pub const CKM_AES_CBC: CK_MECHANISM_TYPE = 0x00001082;
pub const CKM_AES_CBC_PAD: CK_MECHANISM_TYPE = 0x00001085;
pub const CKM_AES_GCM: CK_MECHANISM_TYPE = 0x00001087;
pub const CKM_AES_KEY_WRAP: CK_MECHANISM_TYPE = 0x00002109;

pub const CKA_CLASS: CK_ATTRIBUTE_TYPE = 0x00000000;
pub const CKA_TOKEN: CK_ATTRIBUTE_TYPE = 0x00000001;
pub const CKA_PRIVATE: CK_ATTRIBUTE_TYPE = 0x00000002;
pub const CKA_LABEL: CK_ATTRIBUTE_TYPE = 0x00000003;
pub const CKA_VALUE: CK_ATTRIBUTE_TYPE = 0x00000011;
pub const CKA_CERTIFICATE_TYPE: CK_ATTRIBUTE_TYPE = 0x00000080;
pub const CKA_KEY_TYPE: CK_ATTRIBUTE_TYPE = 0x00000100;
pub const CKA_ID: CK_ATTRIBUTE_TYPE = 0x00000102;
pub const CKA_SENSITIVE: CK_ATTRIBUTE_TYPE = 0x00000103;
pub const CKA_ENCRYPT: CK_ATTRIBUTE_TYPE = 0x00000104;
pub const CKA_DECRYPT: CK_ATTRIBUTE_TYPE = 0x00000105;
pub const CKA_WRAP: CK_ATTRIBUTE_TYPE = 0x00000106;
pub const CKA_UNWRAP: CK_ATTRIBUTE_TYPE = 0x00000107;
pub const CKA_SIGN: CK_ATTRIBUTE_TYPE = 0x00000108;
pub const CKA_SIGN_RECOVER: CK_ATTRIBUTE_TYPE = 0x00000109;
pub const CKA_VERIFY: CK_ATTRIBUTE_TYPE = 0x0000010A;
pub const CKA_VERIFY_RECOVER: CK_ATTRIBUTE_TYPE = 0x0000010B;
pub const CKA_DERIVE: CK_ATTRIBUTE_TYPE = 0x0000010C;
pub const CKA_MODULUS: CK_ATTRIBUTE_TYPE = 0x00000120;
pub const CKA_MODULUS_BITS: CK_ATTRIBUTE_TYPE = 0x00000121;
pub const CKA_PUBLIC_EXPONENT: CK_ATTRIBUTE_TYPE = 0x00000122;
pub const CKA_PRIVATE_EXPONENT: CK_ATTRIBUTE_TYPE = 0x00000123;
pub const CKA_PRIME_1: CK_ATTRIBUTE_TYPE = 0x00000124;
pub const CKA_PRIME_2: CK_ATTRIBUTE_TYPE = 0x00000125;
pub const CKA_EXPONENT_1: CK_ATTRIBUTE_TYPE = 0x00000126;
pub const CKA_EXPONENT_2: CK_ATTRIBUTE_TYPE = 0x00000127;
pub const CKA_COEFFICIENT: CK_ATTRIBUTE_TYPE = 0x00000128;
pub const CKA_VALUE_LEN: CK_ATTRIBUTE_TYPE = 0x00000161;
pub const CKA_EXTRACTABLE: CK_ATTRIBUTE_TYPE = 0x00000162;
pub const CKA_LOCAL: CK_ATTRIBUTE_TYPE = 0x00000163;
pub const CKA_NEVER_EXTRACTABLE: CK_ATTRIBUTE_TYPE = 0x00000164;
pub const CKA_ALWAYS_SENSITIVE: CK_ATTRIBUTE_TYPE = 0x00000165;
pub const CKA_KEY_GEN_MECHANISM: CK_ATTRIBUTE_TYPE = 0x00000166;
pub const CKA_MODIFIABLE: CK_ATTRIBUTE_TYPE = 0x00000170;
pub const CKA_COPYABLE: CK_ATTRIBUTE_TYPE = 0x00000171;
pub const CKA_DESTROYABLE: CK_ATTRIBUTE_TYPE = 0x00000172;
pub const CKA_EC_PARAMS: CK_ATTRIBUTE_TYPE = 0x00000180;
pub const CKA_EC_POINT: CK_ATTRIBUTE_TYPE = 0x00000181;
pub const CKA_ALWAYS_AUTHENTICATE: CK_ATTRIBUTE_TYPE = 0x00000202;

pub const CKF_TOKEN_PRESENT: CK_FLAGS = 0x00000001;
pub const CKF_REMOVABLE_DEVICE: CK_FLAGS = 0x00000002;
pub const CKF_HW_SLOT: CK_FLAGS = 0x00000004;

pub const CKF_RNG: CK_FLAGS = 0x00000001;
pub const CKF_WRITE_PROTECTED: CK_FLAGS = 0x00000002;
pub const CKF_LOGIN_REQUIRED: CK_FLAGS = 0x00000004;
pub const CKF_USER_PIN_INITIALIZED: CK_FLAGS = 0x00000008;
pub const CKF_RESTORE_KEY_NOT_NEEDED: CK_FLAGS = 0x00000020;
pub const CKF_CLOCK_ON_TOKEN: CK_FLAGS = 0x00000040;
pub const CKF_PROTECTED_AUTHENTICATION_PATH: CK_FLAGS = 0x00000100;
pub const CKF_DUAL_CRYPTO_OPERATIONS: CK_FLAGS = 0x00000200;
pub const CKF_TOKEN_INITIALIZED: CK_FLAGS = 0x00000400;
pub const CKF_USER_PIN_COUNT_LOW: CK_FLAGS = 0x00010000;
pub const CKF_USER_PIN_FINAL_TRY: CK_FLAGS = 0x00020000;
pub const CKF_USER_PIN_LOCKED: CK_FLAGS = 0x00040000;
pub const CKF_SO_PIN_COUNT_LOW: CK_FLAGS = 0x00100000;
pub const CKF_SO_PIN_FINAL_TRY: CK_FLAGS = 0x00200000;
pub const CKF_SO_PIN_LOCKED: CK_FLAGS = 0x00400000;

pub const CKF_RW_SESSION: CK_FLAGS = 0x00000002;
pub const CKF_SERIAL_SESSION: CK_FLAGS = 0x00000004;

pub const CKF_HW: CK_FLAGS = 0x00000001;
pub const CKF_ENCRYPT: CK_FLAGS = 0x00000100;
pub const CKF_DECRYPT: CK_FLAGS = 0x00000200;
pub const CKF_DIGEST: CK_FLAGS = 0x00000400;
pub const CKF_SIGN: CK_FLAGS = 0x00000800;
pub const CKF_SIGN_RECOVER: CK_FLAGS = 0x00001000;
pub const CKF_VERIFY: CK_FLAGS = 0x00002000;
pub const CKF_VERIFY_RECOVER: CK_FLAGS = 0x00004000;
pub const CKF_GENERATE: CK_FLAGS = 0x00008000;
pub const CKF_GENERATE_KEY_PAIR: CK_FLAGS = 0x00010000;
pub const CKF_WRAP: CK_FLAGS = 0x00020000;
pub const CKF_UNWRAP: CK_FLAGS = 0x00040000;
pub const CKF_DERIVE: CK_FLAGS = 0x00080000;
pub const CKF_EC_F_P: CK_FLAGS = 0x00100000;
pub const CKF_EC_NAMEDCURVE: CK_FLAGS = 0x00800000;
pub const CKF_EC_UNCOMPRESS: CK_FLAGS = 0x01000000;
pub const CKF_EC_COMPRESS: CK_FLAGS = 0x02000000;

pub const CKF_LIBRARY_CANT_CREATE_OS_THREADS: CK_FLAGS = 0x00000001;
pub const CKF_OS_LOCKING_OK: CK_FLAGS = 0x00000002;

pub const CKF_DONT_BLOCK: CK_FLAGS = 0x00000001;

pub const CKG_MGF1_SHA1: CK_RSA_PKCS_MGF_TYPE = 0x00000001;
pub const CKG_MGF1_SHA256: CK_RSA_PKCS_MGF_TYPE = 0x00000002;
pub const CKG_MGF1_SHA384: CK_RSA_PKCS_MGF_TYPE = 0x00000003;
pub const CKG_MGF1_SHA512: CK_RSA_PKCS_MGF_TYPE = 0x00000004;

pub const CKZ_DATA_SPECIFIED: CK_RSA_PKCS_OAEP_SOURCE_TYPE = 0x00000001;

pub const CK_VERSION = extern struct {
    major: CK_BYTE,
    minor: CK_BYTE,
};

pub const CK_INFO = extern struct {
    cryptokiVersion: CK_VERSION,
    manufacturerID: [32]CK_UTF8CHAR,
    flags: CK_FLAGS,
    libraryDescription: [32]CK_UTF8CHAR,
    libraryVersion: CK_VERSION,
};

pub const CK_SLOT_INFO = extern struct {
    slotDescription: [64]CK_UTF8CHAR,
    manufacturerID: [32]CK_UTF8CHAR,
    flags: CK_FLAGS,
    hardwareVersion: CK_VERSION,
    firmwareVersion: CK_VERSION,
};

pub const CK_TOKEN_INFO = extern struct {
    label: [32]CK_UTF8CHAR,
    manufacturerID: [32]CK_UTF8CHAR,
    model: [16]CK_UTF8CHAR,
    serialNumber: [16]CK_CHAR,
    flags: CK_FLAGS,
    ulMaxSessionCount: CK_ULONG,
    ulSessionCount: CK_ULONG,
    ulMaxRwSessionCount: CK_ULONG,
    ulRwSessionCount: CK_ULONG,
    ulMaxPinLen: CK_ULONG,
    ulMinPinLen: CK_ULONG,
    ulTotalPublicMemory: CK_ULONG,
    ulFreePublicMemory: CK_ULONG,
    ulTotalPrivateMemory: CK_ULONG,
    ulFreePrivateMemory: CK_ULONG,
    hardwareVersion: CK_VERSION,
    firmwareVersion: CK_VERSION,
    utcTime: [16]CK_CHAR,
};

pub const CK_SESSION_INFO = extern struct {
    slotID: CK_SLOT_ID,
    state: CK_STATE,
    flags: CK_FLAGS,
    ulDeviceError: CK_ULONG,
};

pub const CK_MECHANISM_INFO = extern struct {
    ulMinKeySize: CK_ULONG,
    ulMaxKeySize: CK_ULONG,
    flags: CK_FLAGS,
};

pub const CK_ATTRIBUTE = extern struct {
    type: CK_ATTRIBUTE_TYPE,
    pValue: ?*anyopaque,
    ulValueLen: CK_ULONG,
};

pub const CK_MECHANISM = extern struct {
    mechanism: CK_MECHANISM_TYPE,
    pParameter: ?*anyopaque,
    ulParameterLen: CK_ULONG,
};

pub const CK_GCM_PARAMS = extern struct {
    pIv: ?[*]CK_BYTE,
    ulIvLen: CK_ULONG,
    ulIvBits: CK_ULONG,
    pAAD: ?[*]CK_BYTE,
    ulAADLen: CK_ULONG,
    ulTagBits: CK_ULONG,
};

pub const CK_RSA_PKCS_PSS_PARAMS = extern struct {
    hashAlg: CK_MECHANISM_TYPE,
    mgf: CK_RSA_PKCS_MGF_TYPE,
    sLen: CK_ULONG,
};

pub const CK_RSA_PKCS_OAEP_PARAMS = extern struct {
    hashAlg: CK_MECHANISM_TYPE,
    mgf: CK_RSA_PKCS_MGF_TYPE,
    source: CK_RSA_PKCS_OAEP_SOURCE_TYPE,
    pSourceData: ?*anyopaque,
    ulSourceDataLen: CK_ULONG,
};

pub const CK_EC_KDF_TYPE = CK_ULONG;
pub const CKD_NULL: CK_EC_KDF_TYPE = 0x00000001;

pub const CK_ECDH1_DERIVE_PARAMS = extern struct {
    kdf: CK_EC_KDF_TYPE,
    ulSharedDataLen: CK_ULONG,
    pSharedData: ?[*]CK_BYTE,
    ulPublicDataLen: CK_ULONG,
    pPublicData: ?[*]CK_BYTE,
};

pub const CK_DATE = extern struct {
    year: [4]CK_CHAR,
    month: [2]CK_CHAR,
    day: [2]CK_CHAR,
};

pub const CK_NOTIFY = ?*const fn (CK_SESSION_HANDLE, CK_NOTIFICATION, ?*anyopaque) callconv(.c) CK_RV;

pub const CK_CREATEMUTEX = ?*const fn (*?*anyopaque) callconv(.c) CK_RV;
pub const CK_DESTROYMUTEX = ?*const fn (?*anyopaque) callconv(.c) CK_RV;
pub const CK_LOCKMUTEX = ?*const fn (?*anyopaque) callconv(.c) CK_RV;
pub const CK_UNLOCKMUTEX = ?*const fn (?*anyopaque) callconv(.c) CK_RV;

pub const CK_C_INITIALIZE_ARGS = extern struct {
    CreateMutex: CK_CREATEMUTEX,
    DestroyMutex: CK_DESTROYMUTEX,
    LockMutex: CK_LOCKMUTEX,
    UnlockMutex: CK_UNLOCKMUTEX,
    flags: CK_FLAGS,
    pReserved: ?*anyopaque,
};

pub const CK_C_Initialize = ?*const fn (?*anyopaque) callconv(.c) CK_RV;
pub const CK_C_Finalize = ?*const fn (?*anyopaque) callconv(.c) CK_RV;
pub const CK_C_GetInfo = ?*const fn (*CK_INFO) callconv(.c) CK_RV;
pub const CK_C_GetFunctionList = ?*const fn (*?*CK_FUNCTION_LIST) callconv(.c) CK_RV;
pub const CK_C_GetSlotList = ?*const fn (CK_BBOOL, ?[*]CK_SLOT_ID, *CK_ULONG) callconv(.c) CK_RV;
pub const CK_C_GetSlotInfo = ?*const fn (CK_SLOT_ID, *CK_SLOT_INFO) callconv(.c) CK_RV;
pub const CK_C_GetTokenInfo = ?*const fn (CK_SLOT_ID, *CK_TOKEN_INFO) callconv(.c) CK_RV;
pub const CK_C_GetMechanismList = ?*const fn (CK_SLOT_ID, ?[*]CK_MECHANISM_TYPE, *CK_ULONG) callconv(.c) CK_RV;
pub const CK_C_GetMechanismInfo = ?*const fn (CK_SLOT_ID, CK_MECHANISM_TYPE, *CK_MECHANISM_INFO) callconv(.c) CK_RV;
pub const CK_C_InitToken = ?*const fn (CK_SLOT_ID, ?[*]CK_UTF8CHAR, CK_ULONG, ?[*]CK_UTF8CHAR) callconv(.c) CK_RV;
pub const CK_C_InitPIN = ?*const fn (CK_SESSION_HANDLE, ?[*]CK_UTF8CHAR, CK_ULONG) callconv(.c) CK_RV;
pub const CK_C_SetPIN = ?*const fn (CK_SESSION_HANDLE, ?[*]CK_UTF8CHAR, CK_ULONG, ?[*]CK_UTF8CHAR, CK_ULONG) callconv(.c) CK_RV;
pub const CK_C_OpenSession = ?*const fn (CK_SLOT_ID, CK_FLAGS, ?*anyopaque, CK_NOTIFY, *CK_SESSION_HANDLE) callconv(.c) CK_RV;
pub const CK_C_CloseSession = ?*const fn (CK_SESSION_HANDLE) callconv(.c) CK_RV;
pub const CK_C_CloseAllSessions = ?*const fn (CK_SLOT_ID) callconv(.c) CK_RV;
pub const CK_C_GetSessionInfo = ?*const fn (CK_SESSION_HANDLE, *CK_SESSION_INFO) callconv(.c) CK_RV;
pub const CK_C_GetOperationState = ?*const fn (CK_SESSION_HANDLE, ?[*]CK_BYTE, *CK_ULONG) callconv(.c) CK_RV;
pub const CK_C_SetOperationState = ?*const fn (CK_SESSION_HANDLE, [*]CK_BYTE, CK_ULONG, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) callconv(.c) CK_RV;
pub const CK_C_Login = ?*const fn (CK_SESSION_HANDLE, CK_USER_TYPE, ?[*]CK_UTF8CHAR, CK_ULONG) callconv(.c) CK_RV;
pub const CK_C_Logout = ?*const fn (CK_SESSION_HANDLE) callconv(.c) CK_RV;
pub const CK_C_CreateObject = ?*const fn (CK_SESSION_HANDLE, [*]CK_ATTRIBUTE, CK_ULONG, *CK_OBJECT_HANDLE) callconv(.c) CK_RV;
pub const CK_C_CopyObject = ?*const fn (CK_SESSION_HANDLE, CK_OBJECT_HANDLE, [*]CK_ATTRIBUTE, CK_ULONG, *CK_OBJECT_HANDLE) callconv(.c) CK_RV;
pub const CK_C_DestroyObject = ?*const fn (CK_SESSION_HANDLE, CK_OBJECT_HANDLE) callconv(.c) CK_RV;
pub const CK_C_GetObjectSize = ?*const fn (CK_SESSION_HANDLE, CK_OBJECT_HANDLE, *CK_ULONG) callconv(.c) CK_RV;
pub const CK_C_GetAttributeValue = ?*const fn (CK_SESSION_HANDLE, CK_OBJECT_HANDLE, [*]CK_ATTRIBUTE, CK_ULONG) callconv(.c) CK_RV;
pub const CK_C_SetAttributeValue = ?*const fn (CK_SESSION_HANDLE, CK_OBJECT_HANDLE, [*]CK_ATTRIBUTE, CK_ULONG) callconv(.c) CK_RV;
pub const CK_C_FindObjectsInit = ?*const fn (CK_SESSION_HANDLE, ?[*]CK_ATTRIBUTE, CK_ULONG) callconv(.c) CK_RV;
pub const CK_C_FindObjects = ?*const fn (CK_SESSION_HANDLE, [*]CK_OBJECT_HANDLE, CK_ULONG, *CK_ULONG) callconv(.c) CK_RV;
pub const CK_C_FindObjectsFinal = ?*const fn (CK_SESSION_HANDLE) callconv(.c) CK_RV;
pub const CK_C_EncryptInit = ?*const fn (CK_SESSION_HANDLE, *CK_MECHANISM, CK_OBJECT_HANDLE) callconv(.c) CK_RV;
pub const CK_C_Encrypt = ?*const fn (CK_SESSION_HANDLE, [*]CK_BYTE, CK_ULONG, ?[*]CK_BYTE, *CK_ULONG) callconv(.c) CK_RV;
pub const CK_C_EncryptUpdate = ?*const fn (CK_SESSION_HANDLE, [*]CK_BYTE, CK_ULONG, ?[*]CK_BYTE, *CK_ULONG) callconv(.c) CK_RV;
pub const CK_C_EncryptFinal = ?*const fn (CK_SESSION_HANDLE, ?[*]CK_BYTE, *CK_ULONG) callconv(.c) CK_RV;
pub const CK_C_DecryptInit = ?*const fn (CK_SESSION_HANDLE, *CK_MECHANISM, CK_OBJECT_HANDLE) callconv(.c) CK_RV;
pub const CK_C_Decrypt = ?*const fn (CK_SESSION_HANDLE, [*]CK_BYTE, CK_ULONG, ?[*]CK_BYTE, *CK_ULONG) callconv(.c) CK_RV;
pub const CK_C_DecryptUpdate = ?*const fn (CK_SESSION_HANDLE, [*]CK_BYTE, CK_ULONG, ?[*]CK_BYTE, *CK_ULONG) callconv(.c) CK_RV;
pub const CK_C_DecryptFinal = ?*const fn (CK_SESSION_HANDLE, ?[*]CK_BYTE, *CK_ULONG) callconv(.c) CK_RV;
pub const CK_C_DigestInit = ?*const fn (CK_SESSION_HANDLE, *CK_MECHANISM) callconv(.c) CK_RV;
pub const CK_C_Digest = ?*const fn (CK_SESSION_HANDLE, [*]CK_BYTE, CK_ULONG, ?[*]CK_BYTE, *CK_ULONG) callconv(.c) CK_RV;
pub const CK_C_DigestUpdate = ?*const fn (CK_SESSION_HANDLE, [*]CK_BYTE, CK_ULONG) callconv(.c) CK_RV;
pub const CK_C_DigestKey = ?*const fn (CK_SESSION_HANDLE, CK_OBJECT_HANDLE) callconv(.c) CK_RV;
pub const CK_C_DigestFinal = ?*const fn (CK_SESSION_HANDLE, ?[*]CK_BYTE, *CK_ULONG) callconv(.c) CK_RV;
pub const CK_C_SignInit = ?*const fn (CK_SESSION_HANDLE, *CK_MECHANISM, CK_OBJECT_HANDLE) callconv(.c) CK_RV;
pub const CK_C_Sign = ?*const fn (CK_SESSION_HANDLE, [*]CK_BYTE, CK_ULONG, ?[*]CK_BYTE, *CK_ULONG) callconv(.c) CK_RV;
pub const CK_C_SignUpdate = ?*const fn (CK_SESSION_HANDLE, [*]CK_BYTE, CK_ULONG) callconv(.c) CK_RV;
pub const CK_C_SignFinal = ?*const fn (CK_SESSION_HANDLE, ?[*]CK_BYTE, *CK_ULONG) callconv(.c) CK_RV;
pub const CK_C_SignRecoverInit = ?*const fn (CK_SESSION_HANDLE, *CK_MECHANISM, CK_OBJECT_HANDLE) callconv(.c) CK_RV;
pub const CK_C_SignRecover = ?*const fn (CK_SESSION_HANDLE, [*]CK_BYTE, CK_ULONG, ?[*]CK_BYTE, *CK_ULONG) callconv(.c) CK_RV;
pub const CK_C_VerifyInit = ?*const fn (CK_SESSION_HANDLE, *CK_MECHANISM, CK_OBJECT_HANDLE) callconv(.c) CK_RV;
pub const CK_C_Verify = ?*const fn (CK_SESSION_HANDLE, [*]CK_BYTE, CK_ULONG, [*]CK_BYTE, CK_ULONG) callconv(.c) CK_RV;
pub const CK_C_VerifyUpdate = ?*const fn (CK_SESSION_HANDLE, [*]CK_BYTE, CK_ULONG) callconv(.c) CK_RV;
pub const CK_C_VerifyFinal = ?*const fn (CK_SESSION_HANDLE, [*]CK_BYTE, CK_ULONG) callconv(.c) CK_RV;
pub const CK_C_VerifyRecoverInit = ?*const fn (CK_SESSION_HANDLE, *CK_MECHANISM, CK_OBJECT_HANDLE) callconv(.c) CK_RV;
pub const CK_C_VerifyRecover = ?*const fn (CK_SESSION_HANDLE, [*]CK_BYTE, CK_ULONG, ?[*]CK_BYTE, *CK_ULONG) callconv(.c) CK_RV;
pub const CK_C_DigestEncryptUpdate = ?*const fn (CK_SESSION_HANDLE, [*]CK_BYTE, CK_ULONG, ?[*]CK_BYTE, *CK_ULONG) callconv(.c) CK_RV;
pub const CK_C_DecryptDigestUpdate = ?*const fn (CK_SESSION_HANDLE, [*]CK_BYTE, CK_ULONG, ?[*]CK_BYTE, *CK_ULONG) callconv(.c) CK_RV;
pub const CK_C_SignEncryptUpdate = ?*const fn (CK_SESSION_HANDLE, [*]CK_BYTE, CK_ULONG, ?[*]CK_BYTE, *CK_ULONG) callconv(.c) CK_RV;
pub const CK_C_DecryptVerifyUpdate = ?*const fn (CK_SESSION_HANDLE, [*]CK_BYTE, CK_ULONG, ?[*]CK_BYTE, *CK_ULONG) callconv(.c) CK_RV;
pub const CK_C_GenerateKey = ?*const fn (CK_SESSION_HANDLE, *CK_MECHANISM, [*]CK_ATTRIBUTE, CK_ULONG, *CK_OBJECT_HANDLE) callconv(.c) CK_RV;
pub const CK_C_GenerateKeyPair = ?*const fn (CK_SESSION_HANDLE, *CK_MECHANISM, [*]CK_ATTRIBUTE, CK_ULONG, [*]CK_ATTRIBUTE, CK_ULONG, *CK_OBJECT_HANDLE, *CK_OBJECT_HANDLE) callconv(.c) CK_RV;
pub const CK_C_WrapKey = ?*const fn (CK_SESSION_HANDLE, *CK_MECHANISM, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, ?[*]CK_BYTE, *CK_ULONG) callconv(.c) CK_RV;
pub const CK_C_UnwrapKey = ?*const fn (CK_SESSION_HANDLE, *CK_MECHANISM, CK_OBJECT_HANDLE, [*]CK_BYTE, CK_ULONG, [*]CK_ATTRIBUTE, CK_ULONG, *CK_OBJECT_HANDLE) callconv(.c) CK_RV;
pub const CK_C_DeriveKey = ?*const fn (CK_SESSION_HANDLE, *CK_MECHANISM, CK_OBJECT_HANDLE, ?[*]CK_ATTRIBUTE, CK_ULONG, *CK_OBJECT_HANDLE) callconv(.c) CK_RV;
pub const CK_C_SeedRandom = ?*const fn (CK_SESSION_HANDLE, [*]CK_BYTE, CK_ULONG) callconv(.c) CK_RV;
pub const CK_C_GenerateRandom = ?*const fn (CK_SESSION_HANDLE, [*]CK_BYTE, CK_ULONG) callconv(.c) CK_RV;
pub const CK_C_GetFunctionStatus = ?*const fn (CK_SESSION_HANDLE) callconv(.c) CK_RV;
pub const CK_C_CancelFunction = ?*const fn (CK_SESSION_HANDLE) callconv(.c) CK_RV;
pub const CK_C_WaitForSlotEvent = ?*const fn (CK_FLAGS, *CK_SLOT_ID, ?*anyopaque) callconv(.c) CK_RV;

pub const CK_FUNCTION_LIST = extern struct {
    version: CK_VERSION,
    C_Initialize: CK_C_Initialize,
    C_Finalize: CK_C_Finalize,
    C_GetInfo: CK_C_GetInfo,
    C_GetFunctionList: CK_C_GetFunctionList,
    C_GetSlotList: CK_C_GetSlotList,
    C_GetSlotInfo: CK_C_GetSlotInfo,
    C_GetTokenInfo: CK_C_GetTokenInfo,
    C_GetMechanismList: CK_C_GetMechanismList,
    C_GetMechanismInfo: CK_C_GetMechanismInfo,
    C_InitToken: CK_C_InitToken,
    C_InitPIN: CK_C_InitPIN,
    C_SetPIN: CK_C_SetPIN,
    C_OpenSession: CK_C_OpenSession,
    C_CloseSession: CK_C_CloseSession,
    C_CloseAllSessions: CK_C_CloseAllSessions,
    C_GetSessionInfo: CK_C_GetSessionInfo,
    C_GetOperationState: CK_C_GetOperationState,
    C_SetOperationState: CK_C_SetOperationState,
    C_Login: CK_C_Login,
    C_Logout: CK_C_Logout,
    C_CreateObject: CK_C_CreateObject,
    C_CopyObject: CK_C_CopyObject,
    C_DestroyObject: CK_C_DestroyObject,
    C_GetObjectSize: CK_C_GetObjectSize,
    C_GetAttributeValue: CK_C_GetAttributeValue,
    C_SetAttributeValue: CK_C_SetAttributeValue,
    C_FindObjectsInit: CK_C_FindObjectsInit,
    C_FindObjects: CK_C_FindObjects,
    C_FindObjectsFinal: CK_C_FindObjectsFinal,
    C_EncryptInit: CK_C_EncryptInit,
    C_Encrypt: CK_C_Encrypt,
    C_EncryptUpdate: CK_C_EncryptUpdate,
    C_EncryptFinal: CK_C_EncryptFinal,
    C_DecryptInit: CK_C_DecryptInit,
    C_Decrypt: CK_C_Decrypt,
    C_DecryptUpdate: CK_C_DecryptUpdate,
    C_DecryptFinal: CK_C_DecryptFinal,
    C_DigestInit: CK_C_DigestInit,
    C_Digest: CK_C_Digest,
    C_DigestUpdate: CK_C_DigestUpdate,
    C_DigestKey: CK_C_DigestKey,
    C_DigestFinal: CK_C_DigestFinal,
    C_SignInit: CK_C_SignInit,
    C_Sign: CK_C_Sign,
    C_SignUpdate: CK_C_SignUpdate,
    C_SignFinal: CK_C_SignFinal,
    C_SignRecoverInit: CK_C_SignRecoverInit,
    C_SignRecover: CK_C_SignRecover,
    C_VerifyInit: CK_C_VerifyInit,
    C_Verify: CK_C_Verify,
    C_VerifyUpdate: CK_C_VerifyUpdate,
    C_VerifyFinal: CK_C_VerifyFinal,
    C_VerifyRecoverInit: CK_C_VerifyRecoverInit,
    C_VerifyRecover: CK_C_VerifyRecover,
    C_DigestEncryptUpdate: CK_C_DigestEncryptUpdate,
    C_DecryptDigestUpdate: CK_C_DecryptDigestUpdate,
    C_SignEncryptUpdate: CK_C_SignEncryptUpdate,
    C_DecryptVerifyUpdate: CK_C_DecryptVerifyUpdate,
    C_GenerateKey: CK_C_GenerateKey,
    C_GenerateKeyPair: CK_C_GenerateKeyPair,
    C_WrapKey: CK_C_WrapKey,
    C_UnwrapKey: CK_C_UnwrapKey,
    C_DeriveKey: CK_C_DeriveKey,
    C_SeedRandom: CK_C_SeedRandom,
    C_GenerateRandom: CK_C_GenerateRandom,
    C_GetFunctionStatus: CK_C_GetFunctionStatus,
    C_CancelFunction: CK_C_CancelFunction,
    C_WaitForSlotEvent: CK_C_WaitForSlotEvent,
};
