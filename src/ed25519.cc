#include <node.h>
#include <node_buffer.h>

#include <nan.h>

#include "ed25519/ed25519.h"

using namespace v8;
using namespace node;

/**
 * MakeKeypair(Buffer seed)
 * seed: A 32 byte buffer
 * returns: an Object with PublicKey and PrivateKey
 **/
NAN_METHOD(MakeKeypair) {
	NanScope();
	if ((args.Length() < 1) || (!Buffer::HasInstance(args[0])) || (Buffer::Length(args[0]->ToObject()) != 32)) {
		return NanThrowError("MakeKeypair requires a 32 byte buffer");
	}
	const unsigned char* seed = (unsigned char*)Buffer::Data(args[0]->ToObject());

	v8::Local<v8::Object> privateKey = NanNewBufferHandle(64);

	unsigned char* privateKeyData = (unsigned char*)Buffer::Data(privateKey);

	v8::Local<v8::Object> publicKey = NanNewBufferHandle(32);
	unsigned char* publicKeyData = (unsigned char*)Buffer::Data(publicKey);
	for (int i = 0; i < 32; i++)
		privateKeyData[i] = seed[i];
	crypto_sign_keypair(publicKeyData, privateKeyData);

	Local<Object> result = NanNew<Object>();
	result->Set(NanNew("publicKey"), publicKey);
	result->Set(NanNew("privateKey"), privateKey);
	NanReturnValue(result);
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
NAN_METHOD(Sign) {
	NanScope();
	if ((args.Length() < 2) || (!Buffer::HasInstance(args[0]->ToObject()))) {
		return NanThrowError("Sign requires (Buffer, {Buffer(32 or 64) | keyPair object})");
	}
	unsigned char* privateKey;
	if ((Buffer::HasInstance(args[1])) && (Buffer::Length(args[1]->ToObject()) == 32)) {
		unsigned char* seed = (unsigned char*)Buffer::Data(args[1]->ToObject());
		unsigned char publicKeyData[32];
		unsigned char privateKeyData[64];
		for (int i = 0; i < 32; i++) {
			privateKeyData[i] = seed[i];
		}
		crypto_sign_keypair(publicKeyData, privateKeyData);
		privateKey = privateKeyData;
	} else if ((Buffer::HasInstance(args[1])) && (Buffer::Length(args[1]->ToObject()) == 64)) {
		privateKey = (unsigned char*)Buffer::Data(args[1]->ToObject());
	} else if ((args[1]->IsObject()) && (!Buffer::HasInstance(args[1]))) {
		Handle<Object> privateKeyBuffer = args[1]->ToObject()->Get(NanNew<String>("privateKey"))->ToObject();
		if (!Buffer::HasInstance(privateKeyBuffer)) {
			return NanThrowError("Sign requires (Buffer, {Buffer(32 or 64) | keyPair object})");
		}
		privateKey = (unsigned char*)Buffer::Data(privateKeyBuffer);
	} else {
		return NanThrowError("Sign requires (Buffer, {Buffer(32 or 64) | keyPair object})");
	}
	Handle<Object> message = args[0]->ToObject();
	const unsigned char* messageData = (unsigned char*)Buffer::Data(message);
	size_t messageLen = Buffer::Length(message);
	unsigned long long sigLen = 64 + messageLen;
	unsigned char signatureMessageData[sigLen];
	crypto_sign(signatureMessageData, &sigLen, messageData, messageLen, privateKey);

	v8::Local<v8::Object> signature = NanNewBufferHandle(64);
	unsigned char* signatureData = (unsigned char*)Buffer::Data(signature);
	for (int i = 0; i < 64; i++) {
		signatureData[i] = signatureMessageData[i];
	}
	NanReturnValue(signature);
}

/**
 * Verify(Buffer message, Buffer signature, Buffer publicKey)
 * message: message the signature is for
 * signature: signature to be verified
 * publicKey: publicKey to the private key that created the signature
 * returns: boolean
 **/
NAN_METHOD(Verify) {
	NanScope();
	if ((args.Length() < 3) || (!Buffer::HasInstance(args[0]->ToObject())) ||
		(!Buffer::HasInstance(args[1]->ToObject())) || (!Buffer::HasInstance(args[2]->ToObject()))) {
		return NanThrowError("Verify requires (Buffer, Buffer(64), Buffer(32)");
	}
	Handle<Object> message = args[0]->ToObject();
	Handle<Object> signature = args[1]->ToObject();
	Handle<Object> publicKey = args[2]->ToObject();
	if ((Buffer::Length(signature) != 64) || (Buffer::Length(publicKey) != 32)) {
		return NanThrowError("Verify requires (Buffer, Buffer(64), Buffer(32)");
	}
	unsigned char* messageData = (unsigned char*)Buffer::Data(message);
	size_t messageLen = Buffer::Length(message);
	unsigned char* signatureData = (unsigned char*)Buffer::Data(signature);
	unsigned char* publicKeyData = (unsigned char*)Buffer::Data(publicKey);

	NanReturnValue(NanNew(crypto_sign_verify(signatureData, messageData, messageLen, publicKeyData) == 0));
}


void InitModule(Handle<Object> exports) {
	exports->Set(NanNew("MakeKeypair"), NanNew<FunctionTemplate>(MakeKeypair)->GetFunction());
	exports->Set(NanNew("Sign"), NanNew<FunctionTemplate>(Sign)->GetFunction());
	exports->Set(NanNew("Verify"), NanNew<FunctionTemplate>(Verify)->GetFunction());
}

NODE_MODULE(native, InitModule)

