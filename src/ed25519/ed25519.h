#ifndef ED25519_H
#define ED25519_H

#include <stddef.h>

#define ISOLATE(V) v8::Isolate* isolate = (V).GetIsolate();\
  v8::HandleScope scope(isolate);

#define TYPEERROR(E) isolate->ThrowException(v8::Exception::TypeError(v8::String::NewFromUtf8(isolate, ("Error: "#E)))); return;

#ifdef __cplusplus
extern "C" {
#endif

	int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
	int crypto_sign_open(unsigned char *m, unsigned long long *mlen, const unsigned char *sm,
						 unsigned long long smlen, const unsigned char *pk);
	int crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m,
					unsigned long long mlen, const unsigned char *sk);
	int crypto_sign_verify(const unsigned char *signature, const unsigned char *message,
						   size_t message_len, const unsigned char *public_key);
#ifdef __cplusplus
}
#endif

#endif
