#include "ed25519.h"
#include "sha3.h"
#include "ge.h"


JNIEXPORT void JNICALL Java_com_kobaken0029_ed25519_Ed25519_ed25519_create_keypair(
        JNIEnv *env, jclass type, jbyteArray publicKey_, jbyteArray privateKey_, jbyteArray seed_) {

    jbyte *publicKey = (*env)->GetByteArrayElements(env, publicKey_, NULL);
    jbyte *privateKey = (*env)->GetByteArrayElements(env, privateKey_, NULL);
    jbyte *seed = (*env)->GetByteArrayElements(env, seed_, NULL);

    ge_p3 A;

    sha3_512(seed, 32, private_key);
    private_key[0] &= 248;
    private_key[31] &= 63;
    private_key[31] |= 64;

    ge_scalarmult_base(&A, private_key);
    ge_p3_tobytes(public_key, &A);

    (*env)->ReleaseByteArrayElements(env, publicKey_, publicKey, 0);
    (*env)->ReleaseByteArrayElements(env, privateKey_, privateKey, 0);
    (*env)->ReleaseByteArrayElements(env, seed_, seed, 0);
}
