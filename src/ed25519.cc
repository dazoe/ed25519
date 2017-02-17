#include <node.h>
#include <node_buffer.h>
#include <stdlib.h>
#include "ed25519/ed25519.h"

using namespace v8;
using namespace node;

/**
 * MakeKeypair(Buffer seed)
 * seed: A 32 byte buffer
 * returns: an Object with PublicKey and PrivateKey
 **/
static void MakeKeypair(const v8::FunctionCallbackInfo<v8::Value>& info) {
	ISOLATE(info);
	if ((info.Length() < 1) || (!Buffer::HasInstance(info[0])) || (Buffer::Length(info[0]->ToObject()) != 32)) {
		TYPEERROR(MakeKeypair requires a 32 byte buffer)
	}
	const unsigned char* seed = (unsigned char*)Buffer::Data(info[0]->ToObject());

	v8::Local<v8::Object> privateKey = node::Buffer::New(isolate, 64).ToLocalChecked();

	unsigned char* privateKeyData = (unsigned char*)Buffer::Data(privateKey);

	v8::Local<v8::Object> publicKey = node::Buffer::New(isolate, 32).ToLocalChecked();
	unsigned char* publicKeyData = (unsigned char*)Buffer::Data(publicKey);
	for (int i = 0; i < 32; i++)
		privateKeyData[i] = seed[i];
	crypto_sign_keypair(publicKeyData, privateKeyData);

	v8::Local<v8::Object> result = v8::Object::New(isolate);
	result->Set(v8::String::NewFromUtf8(isolate, "publicKey"), publicKey);
	result->Set(v8::String::NewFromUtf8(isolate, "privateKey"), privateKey);
	info.GetReturnValue().Set(result);
}

/**
 * Sign(Buffer message, Buffer seed)
 * Sign(Buffer message, Buffer privateKey)
 * Sign(Buffer message, Object keyPair)
 * message: the message to be signed
 * seed: 32 byte buffer to make a keypair
 * keyPair: the object from the MakeKeypair function
 * returns: the signature as a Buffer
 **/
static void Sign(const v8::FunctionCallbackInfo<v8::Value>& info) {
	ISOLATE(info);
	unsigned char* privateKey;

	if ((info.Length() < 2) || (!Buffer::HasInstance(info[0]->ToObject()))) {
		TYPEERROR(Sign requires (Buffer, {Buffer(32 or 64) | keyPair object}))
	}
	if ((Buffer::HasInstance(info[1])) && (Buffer::Length(info[1]->ToObject()) == 32)) {
		unsigned char* seed = (unsigned char*)Buffer::Data(info[1]->ToObject());
		unsigned char publicKeyData[32];
		unsigned char privateKeyData[64];
		for (int i = 0; i < 32; i++) {
			privateKeyData[i] = seed[i];
		}
		crypto_sign_keypair(publicKeyData, privateKeyData);
		privateKey = privateKeyData;
	} else if ((Buffer::HasInstance(info[1])) && (Buffer::Length(info[1]->ToObject()) == 64)) {
		privateKey = (unsigned char*)Buffer::Data(info[1]->ToObject());
	} else if ((info[1]->IsObject()) && (!Buffer::HasInstance(info[1]))) {
		Local<Value> privateKeyBuffer = info[1]->ToObject()->Get(v8::String::NewFromUtf8(isolate, "privateKey"))->ToObject();
		if (!Buffer::HasInstance(privateKeyBuffer)) {
			TYPEERROR(Sign requires (Buffer, {Buffer(32 or 64) | keyPair object}))
		}
		privateKey = (unsigned char*)Buffer::Data(privateKeyBuffer);
	} else {
		TYPEERROR(Sign requires (Buffer, {Buffer(32 or 64) | keyPair object}))
	}
	Handle<Object> message = info[0]->ToObject();
	const unsigned char* messageData = (unsigned char*)Buffer::Data(message);
	size_t messageLen = Buffer::Length(message);
	unsigned long long sigLen = 64 + messageLen;
	unsigned char *signatureMessageData = (unsigned char*) malloc(sigLen);
	crypto_sign(signatureMessageData, &sigLen, messageData, messageLen, privateKey);

	v8::Local<v8::Object> signature = node::Buffer::New(isolate, 64).ToLocalChecked();
	unsigned char* signatureData = (unsigned char*)Buffer::Data(signature);
	for (int i = 0; i < 64; i++) {
		signatureData[i] = signatureMessageData[i];
	}

	free(signatureMessageData);
	info.GetReturnValue().Set(signature);
}

/**
 * Verify(Buffer message, Buffer signature, Buffer publicKey)
 * message: message the signature is for
 * signature: signature to be verified
 * publicKey: publicKey to the private key that created the signature
 * returns: boolean
 **/
static void Verify(const v8::FunctionCallbackInfo<v8::Value>& info) {
	ISOLATE(info);
	if ((info.Length() < 3) || (!Buffer::HasInstance(info[0]->ToObject())) ||
		(!Buffer::HasInstance(info[1]->ToObject())) || (!Buffer::HasInstance(info[2]->ToObject()))) {
		TYPEERROR(Verify requires Buffer, Buffer(64), Buffer(32))
	}
	Handle<Object> message = info[0]->ToObject();
	Handle<Object> signature = info[1]->ToObject();
	Handle<Object> publicKey = info[2]->ToObject();
	if ((Buffer::Length(signature) != 64) || (Buffer::Length(publicKey) != 32)) {
		TYPEERROR(Verify requires (Buffer, Buffer(64), Buffer(32)))
	}
	unsigned char* messageData = (unsigned char*)Buffer::Data(message);
	size_t messageLen = Buffer::Length(message);
	unsigned char* signatureData = (unsigned char*)Buffer::Data(signature);
	unsigned char* publicKeyData = (unsigned char*)Buffer::Data(publicKey);

	info.GetReturnValue().Set(crypto_sign_verify(signatureData, messageData, messageLen, publicKeyData) == 0);
}

void InitModule(v8::Local<v8::Object> exports) {
	NODE_SET_METHOD(exports, "MakeKeypair", MakeKeypair);
	NODE_SET_METHOD(exports, "Sign", Sign);
	NODE_SET_METHOD(exports, "Verify", Verify);
}

NODE_MODULE(ed25519, InitModule)
