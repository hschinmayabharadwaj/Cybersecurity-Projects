# Vendored PKCS#11 headers

`pkcs11.h`, `pkcs11t.h`, and `pkcs11f.h` are the **canonical OASIS headers**, fetched
**unmodified** from the published v2.40 errata-01 OASIS Standard:

```
https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/include/pkcs11-v2.40/
```

They retain their original OASIS copyright notices and are **not** covered by this
project's license. They are vendored for one purpose only: a build-time ABI
cross-check (`zig build test`) that proves the hand-written Cryptoki ABI in
`src/ck.zig` matches the spec byte-for-byte.

## Integrity

SHA-256 of the vendored headers as fetched (verify with `sha256sum -c` after
re-fetching from the URL above):

```
8bb7aa1aeaa328b6a39913070d6f3d2bdeb9f2c92baf27f714fbb4cbefdf4054  pkcs11.h
5b58736b6d23f12b4d9492cd24b06b9d11056c3153afc4e89b1fe564749e71a2  pkcs11t.h
a85adad038bfc9dad9c71377f3ed3b049ba2ac9b3f37198a372f211d210c6057  pkcs11f.h
```

`shim.h` is the only file here authored by this project. It defines the five
caller-supplied macros the OASIS headers require (`CK_PTR`,
`CK_DECLARE_FUNCTION`, `CK_DECLARE_FUNCTION_POINTER`, `CK_CALLBACK_FUNCTION`,
`NULL_PTR`) and then includes `pkcs11.h`. `build.zig` runs `addTranslateC` on
`shim.h`; `tests/abi_test.zig` then asserts `@sizeOf`/`@offsetOf`/constant
equality between `src/ck.zig` and the translated headers.

The production `.so` does **not** depend on these headers — it ships the pure
hand-written `src/ck.zig`. These exist for regression-hardening of that file.
