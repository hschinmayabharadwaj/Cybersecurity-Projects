// ©AngelaMos | 2026
// config.zig

const ck = @import("ck.zig");

pub const cryptoki_version: ck.CK_VERSION = .{ .major = 2, .minor = 40 };
pub const library_version: ck.CK_VERSION = .{ .major = 0, .minor = 1 };
pub const hardware_version: ck.CK_VERSION = .{ .major = 1, .minor = 0 };
pub const firmware_version: ck.CK_VERSION = .{ .major = 0, .minor = 1 };

pub const manufacturer_id = "Angelamos";
pub const library_description = "Zig HSM Emulator";
pub const slot_description = "AngelaMos HSM Emulator Slot 0";
pub const token_label = "AngelaMos-HSM";
pub const token_model = "hsm-emu";
pub const token_serial = "0000000000000001";

pub const slot_id: ck.CK_SLOT_ID = 0;
pub const slot_count: ck.CK_ULONG = 1;
pub const max_sessions: ck.CK_ULONG = 64;

pub const min_pin_len: ck.CK_ULONG = 4;
pub const max_pin_len: ck.CK_ULONG = 255;

pub const aes_min_key_bytes: ck.CK_ULONG = 16;
pub const aes_max_key_bytes: ck.CK_ULONG = 32;
pub const rsa_min_key_bits: ck.CK_ULONG = 2048;
pub const rsa_max_key_bits: ck.CK_ULONG = 4096;
pub const ec_min_key_bits: ck.CK_ULONG = 256;
pub const ec_max_key_bits: ck.CK_ULONG = 384;
pub const ec_keygen_max_attempts: usize = 8;
pub const hmac_min_key_bytes: ck.CK_ULONG = 32;
pub const hmac_max_key_bytes: ck.CK_ULONG = 64;

pub const pin_kdf_t: u32 = 3;
pub const pin_kdf_m_kib: u32 = 65536;
pub const pin_kdf_p: u24 = 1;
pub const pin_salt_len: usize = 16;
pub const pin_hash_len: usize = 32;

pub const login_max_attempts: ck.CK_ULONG = 3;

pub const token_path_env = "ANGELAMOS_HSM_TOKEN";
pub const token_path_default = ".angelamos-hsm-token";
pub const token_record_magic: u32 = 0x484D5331;
pub const token_record_version: u32 = 2;
pub const path_buf_len: usize = 4096;
pub const token_read_limit: usize = 512;
pub const label_len: usize = 32;

pub const object_path_env = "ANGELAMOS_HSM_OBJECTS";
pub const object_path_default = ".angelamos-hsm-objects";
pub const object_record_magic: u32 = 0x484D4F31;
pub const object_record_version: u32 = 2;
pub const object_read_limit: usize = 4 * 1024 * 1024;
pub const max_objects: usize = 256;
pub const max_attributes_per_object: usize = 64;
pub const max_attr_value_len: usize = 64 * 1024;

pub const aes_block_len: usize = 16;
pub const gcm_iv_len: usize = 12;
pub const gcm_iv_bits: ck.CK_ULONG = 96;
pub const gcm_tag_len: usize = 16;
pub const gcm_tag_bits: ck.CK_ULONG = 128;
pub const max_gcm_aad_len: usize = 256;
pub const max_gcm_stream_len: usize = 16 * 1024 * 1024;

pub const master_key_len: usize = 32;

pub const op_state_version: u8 = 1;
pub const op_state_header_len: usize = 2;

pub const supported_mechanisms = [_]ck.CK_MECHANISM_TYPE{
    ck.CKM_SHA256,
    ck.CKM_SHA384,
    ck.CKM_SHA512,
    ck.CKM_SHA256_HMAC,
    ck.CKM_SHA384_HMAC,
    ck.CKM_SHA512_HMAC,
    ck.CKM_AES_KEY_GEN,
    ck.CKM_AES_CBC,
    ck.CKM_AES_CBC_PAD,
    ck.CKM_AES_GCM,
    ck.CKM_EC_KEY_PAIR_GEN,
    ck.CKM_ECDSA,
    ck.CKM_ECDSA_SHA256,
    ck.CKM_ECDH1_DERIVE,
    ck.CKM_RSA_PKCS_KEY_PAIR_GEN,
    ck.CKM_RSA_PKCS,
    ck.CKM_SHA256_RSA_PKCS,
    ck.CKM_RSA_PKCS_PSS,
    ck.CKM_SHA256_RSA_PKCS_PSS,
    ck.CKM_RSA_PKCS_OAEP,
    ck.CKM_AES_KEY_WRAP,
};
