#include <node.h>
#include <node_buffer.h>

#include <nan.h>
#include <stdlib.h>

#include "ed25519/ed25519.h"

using namespace v8;
using namespace node;

/**
 * MakeKeypair(Buffer seed)
 * seed: A 32 byte buffer
 * returns: an Object with PublicKey and PrivateKey
 **/
NAN_METHOD(MakeKeypair) {
	Nan::HandleScope scope;
	v8::Local<v8::Value> bufferObj;
	if (info.Length() < 1 ||
	    !info[0]->ToObject(Nan::GetCurrentContext()).ToLocal(&bufferObj) ||
		!Buffer::HasInstance(bufferObj))
	{
		return Nan::ThrowError("MakeKeypair requires a Buffer parameter");
	}
	if (Buffer::Length(bufferObj) != 32) {
		return Nan::ThrowError("MakeKeypair requires a 32 byte buffer");
	}

	const unsigned char* seed = (unsigned char*)Buffer::Data(bufferObj);

	v8::Local<v8::Object> privateKey = Nan::NewBuffer(64).ToLocalChecked();

	unsigned char* privateKeyData = (unsigned char*)Buffer::Data(privateKey);

	v8::Local<v8::Object> publicKey = Nan::NewBuffer(32).ToLocalChecked();
	unsigned char* publicKeyData = (unsigned char*)Buffer::Data(publicKey);
	for (int i = 0; i < 32; i++) {
		privateKeyData[i] = seed[i];
	}
	crypto_sign_keypair(publicKeyData, privateKeyData);

	Local<Object> result = Nan::New<Object>();
	result->Set(Nan::GetCurrentContext(), Nan::New("publicKey").ToLocalChecked(), publicKey);
	result->Set(Nan::GetCurrentContext(), Nan::New("privateKey").ToLocalChecked(), privateKey);
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
NAN_METHOD(Sign) {
	Nan::HandleScope scope;
	unsigned char* privateKey;

	v8::Local<v8::Object> messageObj;
	v8::Local<v8::Object> obj1;
	if (info.Length() < 2 ||
	    !info[0]->ToObject(Nan::GetCurrentContext()).ToLocal(&messageObj) ||
		!Buffer::HasInstance(messageObj) ||
	    !info[1]->ToObject(Nan::GetCurrentContext()).ToLocal(&obj1)) {
		return Nan::ThrowError("Sign requires (Buffer, {Buffer(32 or 64) | keyPair object})");
	}
	unsigned char privateKeyData[64]; //put this variable here because of the bug on mac
	bool obj1IsBuffer = Buffer::HasInstance(obj1);
	size_t obj1BufferLength = obj1IsBuffer ? Buffer::Length(obj1) : 0;
	if (obj1IsBuffer && obj1BufferLength == 32) {
		unsigned char* seed = (unsigned char*)Buffer::Data(obj1);
		unsigned char publicKeyData[32];
		for (int i = 0; i < 32; i++) {
			privateKeyData[i] = seed[i];
		}
		crypto_sign_keypair(publicKeyData, privateKeyData);
		privateKey = privateKeyData;
	} else if (obj1IsBuffer && obj1BufferLength == 64) {
		privateKey = (unsigned char*)Buffer::Data(obj1);
	} else if (obj1->IsObject() && !obj1IsBuffer) {
		v8::Local<v8::Value> privateKeyPropertyObj;
		v8::Local<v8::Object> privateKeyBufferObj;
		if (!(obj1->Get(Nan::GetCurrentContext(), Nan::New<String>("privateKey").ToLocalChecked())).ToLocal(&privateKeyPropertyObj) ||
			!privateKeyPropertyObj->ToObject(Nan::GetCurrentContext()).ToLocal(&privateKeyBufferObj) ||
			!Buffer::HasInstance(privateKeyBufferObj)) {
			return Nan::ThrowError("Sign requires (Buffer, {Buffer(32 or 64) | keyPair object})");
		}
		privateKey = (unsigned char*)Buffer::Data(privateKeyBufferObj);
	} else {
		return Nan::ThrowError("Sign requires (Buffer, {Buffer(32 or 64) | keyPair object})");
	}

	const unsigned char* messageData = (unsigned char*)Buffer::Data(messageObj);
	size_t messageLen = Buffer::Length(messageObj);
	unsigned long long sigLen = 64 + messageLen;
	unsigned char *signatureMessageData = (unsigned char*) malloc(sigLen);
	crypto_sign(signatureMessageData, &sigLen, messageData, messageLen, privateKey);

	v8::Local<v8::Object> signature = Nan::NewBuffer(64).ToLocalChecked();
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
NAN_METHOD(Verify) {
	v8::Local<v8::Object> message;
	v8::Local<v8::Object> signature;
	v8::Local<v8::Object> publicKey;
	if (info.Length() < 3 ||
	    !info[0]->ToObject(Nan::GetCurrentContext()).ToLocal(&message) ||
		!Buffer::HasInstance(message) ||
	    !info[1]->ToObject(Nan::GetCurrentContext()).ToLocal(&signature) ||
		!Buffer::HasInstance(signature) ||
		Buffer::Length(signature) != 64 ||
	    !info[2]->ToObject(Nan::GetCurrentContext()).ToLocal(&publicKey) ||
		!Buffer::HasInstance(publicKey) ||
		Buffer::Length(publicKey) != 32) {
		return Nan::ThrowError("Verify requires (Buffer, Buffer(64), Buffer(32)");
	}

	unsigned char* messageData = (unsigned char*)Buffer::Data(message);
	size_t messageLen = Buffer::Length(message);
	unsigned char* signatureData = (unsigned char*)Buffer::Data(signature);
	unsigned char* publicKeyData = (unsigned char*)Buffer::Data(publicKey);

	info.GetReturnValue().Set(crypto_sign_verify(signatureData, messageData, messageLen, publicKeyData) == 0);
}


void InitModule(v8::Local<v8::Object> exports) {
	Nan::SetMethod(exports, "MakeKeypair", MakeKeypair);
	Nan::SetMethod(exports, "Sign", Sign);
	Nan::SetMethod(exports, "Verify", Verify);
}

NODE_MODULE(ed25519, InitModule)
