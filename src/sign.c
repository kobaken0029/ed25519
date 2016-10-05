#include "ed25519.h"
#include "sha3.h"
#include "ge.h"
#include "sc.h"


JNIEXPORT void JNICALL Java_com_kobaken0029_ed25519_Ed25519_ed25519_sign(
    JNIEnv *env, jclass type, jbyteArray signature, jbyteArray message, jint message_len, jbyteArray public_key, jbyteArray private_key) {

    jbyte *signature = (*env)->GetByteArrayElements(env, signature_, NULL);
    jbyte *message = (*env)->GetByteArrayElements(env, message_, NULL);
    jbyte *public_key = (*env)->GetByteArrayElements(env, public_key_, NULL);
    jbyte *private_key = (*env)->GetByteArrayElements(env, private_key_, NULL);

    sha3_context hash;
    unsigned char hram[64];
    unsigned char r[64];
    ge_p3 R;


    sha3_Init512(&hash);
    sha3_Update(&hash, private_key + 32, 32);
    sha3_Update(&hash, message, message_len);
    sha3_Finalize(&hash, r);

    sc_reduce(r);
    ge_scalarmult_base(&R, r);
    ge_p3_tobytes(signature, &R);

    sha3_Init512(&hash);
    sha3_Update(&hash, signature, 32);
    sha3_Update(&hash, public_key, 32);
    sha3_Update(&hash, message, message_len);
    sha3_Finalize(&hash, hram);

    sc_reduce(hram);
    sc_muladd(signature + 32, hram, private_key, r);

    jbyte *signature = (*env)->GetByteArrayElements(env, signature_, NULL);
    jbyte *message = (*env)->GetByteArrayElements(env, message_, NULL);
    jbyte *public_key = (*env)->GetByteArrayElements(env, public_key_, NULL);
    jbyte *private_key = (*env)->GetByteArrayElements(env, private_key_, NULL);
}
