// ©AngelaMos | 2026
// shim.h

#ifndef ANGELAMOS_PKCS11_SHIM_H
#define ANGELAMOS_PKCS11_SHIM_H

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (*name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "pkcs11.h"

#endif
