#ifndef ED25519_H
#define ED25519_H

#include <stddef.h>

#if defined(_WIN32)
    #if defined(ED25519_BUILD_DLL)
        #define ED25519_DECLSPEC __declspec(dllexport)
    #elif defined(ED25519_DLL)
        #define ED25519_DECLSPEC __declspec(dllimport)
    #else
        #define ED25519_DECLSPEC
    #endif
#else
    #define ED25519_DECLSPEC
#endif


#ifdef __cplusplus
extern "C" {
#endif

#ifndef ED25519_NO_SEED
JNIEXPORT jint JNICALL Java_com_kobaken0029_ed25519_Ed25519_ed25519_create_seed(
    JNIEnv *env, jclass type, jbyteArray seed_);
#endif

JNIEXPORT void JNICALL Java_com_kobaken0029_ed25519_Ed25519_ed25519_create_keypair(
    JNIEnv *env, jclass type, jbyteArray publicKey_, jbyteArray privateKey_, jbyteArray seed_);
JNIEXPORT void JNICALL Java_com_kobaken0029_ed25519_Ed25519_ed25519_sign(
    JNIEnv *env, jclass type, jbyteArray signature, jbyteArray message, jint message_len, jbyteArray public_key, jbyteArray private_key);
JNIEXPORT jint JNICALL Java_com_kobaken0029_ed25519_Ed25519_ed25519_verify(
    JNIEnv *env, jclass type, jbyteArray signature_, jbyteArray message_, jint message_len, jbyteArray public_key_);
JNIEXPORT void JNICALL Java_com_kobaken0029_ed25519_Ed25519_ed25519_add_scalar(
    JNIEnv *env, jclass type, jbyteArray public_key_, jbyteArray private_key_, jbyteArray scalar_);
JNIEXPORT void JNICALL Java_com_kobaken0029_ed25519_Ed25519_ed25519_key_exchange(
    JNIEnv *env, jclass type, jbyteArray shared_secret_, jbyteArray public_key_, jbyteArray private_key_);


#ifdef __cplusplus
}
#endif

#endif
