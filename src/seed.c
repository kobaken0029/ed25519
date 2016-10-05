#include "ed25519.h"

#ifndef ED25519_NO_SEED

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <stdio.h>
#endif

JNIEXPORT jint JNICALL Java_com_kobaken0029_ed25519_Ed25519_ed25519_create_seed(
        JNIEnv *env, jclass type, jbyteArray seed_) {

    jbyte *seed = (*env)->GetByteArrayElements(env, seed_, NULL);

#ifdef _WIN32
    HCRYPTPROV prov;

    if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))  {
        (*env)->ReleaseByteArrayElements(env, seed_, seed, 0);
        return 1;
    }

    if (!CryptGenRandom(prov, 32, seed))  {
        CryptReleaseContext(prov, 0);
        (*env)->ReleaseByteArrayElements(env, seed_, seed, 0);
        return 1;
    }

    CryptReleaseContext(prov, 0);
#else
    FILE *f = fopen("/dev/urandom", "rb");

    if (f == NULL) {
        (*env)->ReleaseByteArrayElements(env, seed_, seed, 0);
        return 1;
    }

    fread(seed, 1, 32, f);
    fclose(f);
#endif

    (*env)->ReleaseByteArrayElements(env, seed_, seed, 0);
    return 0;
}

#endif
