// ©AngelaMos | 2026
// openssl.zig

pub const EVP_PKEY = opaque {};
pub const EVP_PKEY_CTX = opaque {};
pub const EVP_MD = opaque {};
pub const EVP_MD_CTX = opaque {};
pub const ENGINE = opaque {};
pub const BIGNUM = opaque {};
pub const OSSL_LIB_CTX = opaque {};
pub const OSSL_PARAM = opaque {};
pub const OSSL_PARAM_BLD = opaque {};

pub const pkey_rsa: c_int = 6;
pub const selection_public_key: c_int = 134;
pub const selection_keypair: c_int = 135;

pub const pad_pkcs1: c_int = 1;
pub const pad_oaep: c_int = 4;
pub const pad_pss: c_int = 6;
pub const pss_saltlen_digest: c_int = -1;

pub const param_n = "n";
pub const param_e = "e";
pub const param_d = "d";
pub const param_factor1 = "rsa-factor1";
pub const param_factor2 = "rsa-factor2";
pub const param_exponent1 = "rsa-exponent1";
pub const param_exponent2 = "rsa-exponent2";
pub const param_coefficient1 = "rsa-coefficient1";

pub extern fn EVP_PKEY_CTX_new_id(id: c_int, e: ?*ENGINE) ?*EVP_PKEY_CTX;
pub extern fn EVP_PKEY_CTX_new(pkey: ?*EVP_PKEY, e: ?*ENGINE) ?*EVP_PKEY_CTX;
pub extern fn EVP_PKEY_CTX_new_from_name(libctx: ?*OSSL_LIB_CTX, name: [*:0]const u8, propq: ?[*:0]const u8) ?*EVP_PKEY_CTX;
pub extern fn EVP_PKEY_CTX_free(ctx: ?*EVP_PKEY_CTX) void;
pub extern fn EVP_PKEY_free(pkey: ?*EVP_PKEY) void;

pub extern fn EVP_PKEY_keygen_init(ctx: ?*EVP_PKEY_CTX) c_int;
pub extern fn EVP_PKEY_CTX_set_rsa_keygen_bits(ctx: ?*EVP_PKEY_CTX, bits: c_int) c_int;
pub extern fn EVP_PKEY_generate(ctx: ?*EVP_PKEY_CTX, ppkey: *?*EVP_PKEY) c_int;

pub extern fn EVP_PKEY_get_bits(pkey: ?*const EVP_PKEY) c_int;
pub extern fn EVP_PKEY_get_bn_param(pkey: ?*const EVP_PKEY, key_name: [*:0]const u8, bn: *?*BIGNUM) c_int;

pub extern fn EVP_PKEY_fromdata_init(ctx: ?*EVP_PKEY_CTX) c_int;
pub extern fn EVP_PKEY_fromdata(ctx: ?*EVP_PKEY_CTX, ppkey: *?*EVP_PKEY, selection: c_int, params: ?*OSSL_PARAM) c_int;

pub extern fn BN_bin2bn(s: [*]const u8, len: c_int, ret: ?*BIGNUM) ?*BIGNUM;
pub extern fn BN_bn2binpad(a: ?*const BIGNUM, to: [*]u8, tolen: c_int) c_int;
pub extern fn BN_num_bits(a: ?*const BIGNUM) c_int;
pub extern fn BN_free(a: ?*BIGNUM) void;
pub extern fn BN_clear_free(a: ?*BIGNUM) void;

pub extern fn OSSL_PARAM_BLD_new() ?*OSSL_PARAM_BLD;
pub extern fn OSSL_PARAM_BLD_push_BN(bld: ?*OSSL_PARAM_BLD, key: [*:0]const u8, bn: ?*const BIGNUM) c_int;
pub extern fn OSSL_PARAM_BLD_to_param(bld: ?*OSSL_PARAM_BLD) ?*OSSL_PARAM;
pub extern fn OSSL_PARAM_BLD_free(bld: ?*OSSL_PARAM_BLD) void;
pub extern fn OSSL_PARAM_free(p: ?*OSSL_PARAM) void;

pub extern fn EVP_MD_CTX_new() ?*EVP_MD_CTX;
pub extern fn EVP_MD_CTX_free(ctx: ?*EVP_MD_CTX) void;
pub extern fn EVP_sha256() ?*const EVP_MD;
pub extern fn EVP_sha384() ?*const EVP_MD;
pub extern fn EVP_sha512() ?*const EVP_MD;

pub extern fn EVP_DigestSignInit(ctx: ?*EVP_MD_CTX, pctx: ?*?*EVP_PKEY_CTX, mdtype: ?*const EVP_MD, e: ?*ENGINE, pkey: ?*EVP_PKEY) c_int;
pub extern fn EVP_DigestSign(ctx: ?*EVP_MD_CTX, sigret: ?[*]u8, siglen: *usize, tbs: [*]const u8, tbslen: usize) c_int;
pub extern fn EVP_DigestVerifyInit(ctx: ?*EVP_MD_CTX, pctx: ?*?*EVP_PKEY_CTX, mdtype: ?*const EVP_MD, e: ?*ENGINE, pkey: ?*EVP_PKEY) c_int;
pub extern fn EVP_DigestVerify(ctx: ?*EVP_MD_CTX, sig: [*]const u8, siglen: usize, tbs: [*]const u8, tbslen: usize) c_int;

pub extern fn EVP_PKEY_sign_init(ctx: ?*EVP_PKEY_CTX) c_int;
pub extern fn EVP_PKEY_sign(ctx: ?*EVP_PKEY_CTX, sig: ?[*]u8, siglen: *usize, tbs: [*]const u8, tbslen: usize) c_int;
pub extern fn EVP_PKEY_verify_init(ctx: ?*EVP_PKEY_CTX) c_int;
pub extern fn EVP_PKEY_verify(ctx: ?*EVP_PKEY_CTX, sig: [*]const u8, siglen: usize, tbs: [*]const u8, tbslen: usize) c_int;
pub extern fn EVP_PKEY_verify_recover_init(ctx: ?*EVP_PKEY_CTX) c_int;
pub extern fn EVP_PKEY_verify_recover(ctx: ?*EVP_PKEY_CTX, rout: ?[*]u8, routlen: *usize, sig: [*]const u8, siglen: usize) c_int;

pub extern fn EVP_PKEY_encrypt_init(ctx: ?*EVP_PKEY_CTX) c_int;
pub extern fn EVP_PKEY_encrypt(ctx: ?*EVP_PKEY_CTX, out: ?[*]u8, outlen: *usize, in: [*]const u8, inlen: usize) c_int;
pub extern fn EVP_PKEY_decrypt_init(ctx: ?*EVP_PKEY_CTX) c_int;
pub extern fn EVP_PKEY_decrypt(ctx: ?*EVP_PKEY_CTX, out: ?[*]u8, outlen: *usize, in: [*]const u8, inlen: usize) c_int;

pub extern fn EVP_PKEY_CTX_set_rsa_padding(ctx: ?*EVP_PKEY_CTX, pad_mode: c_int) c_int;
pub extern fn EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx: ?*EVP_PKEY_CTX, saltlen: c_int) c_int;
pub extern fn EVP_PKEY_CTX_set_rsa_mgf1_md(ctx: ?*EVP_PKEY_CTX, md: ?*const EVP_MD) c_int;
pub extern fn EVP_PKEY_CTX_set_rsa_oaep_md(ctx: ?*EVP_PKEY_CTX, md: ?*const EVP_MD) c_int;
pub extern fn EVP_PKEY_CTX_set_signature_md(ctx: ?*EVP_PKEY_CTX, md: ?*const EVP_MD) c_int;
