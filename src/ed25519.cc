#include <node.h>
#include <node_buffer.h>
#include "ed25519/ed25519.h"
#include "ed25519/ge.h"

using namespace v8;
using namespace node;

//Helper function
static Handle<Value> V8Exception(const char* msg) {
	return ThrowException(Exception::Error(String::New(msg)));
}

static void MakeKeypairFromPrivateKey(unsigned char* privateKey, unsigned char* publicKey) {
	ge_p3 A;
	privateKey[0] &= 248;
	privateKey[31] &= 63;
	privateKey[31] |= 64;
	ge_scalarmult_base(&A, privateKey);
	ge_p3_tobytes(publicKey, &A);
}

/**
 * MakeKeypairFromSeed(Buffer seed)
 * seed: A 32 byte buffer
 * returns: an Object with PublicKey and PrivateKey
 **/
Handle<Value> MakeKeypairFromSeed(const Arguments& args) {
	HandleScope scope;
	if ((args.Length() < 1) || (!Buffer::HasInstance(args[0])) || (Buffer::Length(args[0]->ToObject()) != 32)) {
		return V8Exception("MakeKeypair requires a 32 byte buffer");
	}
	const unsigned char* seed = (unsigned char*)Buffer::Data(args[0]->ToObject());
	Buffer* privateKey = Buffer::New(64);
	unsigned char* privateKeyData = (unsigned char*)Buffer::Data(privateKey);
	Buffer* publicKey = Buffer::New(32);
	unsigned char* publicKeyData = (unsigned char*)Buffer::Data(publicKey);
	ed25519_create_keypair(publicKeyData, privateKeyData, seed);

	Local<Object> result = Object::New();
	result->Set(String::NewSymbol("publicKey"), Local<Object>::New(publicKey->handle_));
	result->Set(String::NewSymbol("privateKey"), Local<Object>::New(privateKey->handle_));
	return scope.Close(result);
}

/**
 * MakeKeypairFrom512Hash(Buffer hash)
 * hash: A 64 byte buffer (sha512 prefered)
 * returns: an Object with PublicKey and PrivateKey
 **/
Handle<Value> MakeKeypairFrom512Hash(const Arguments& args) {
	HandleScope scope;
	if ((args.Length() < 1) || (!Buffer::HasInstance(args[0])) || (Buffer::Length(args[0]->ToObject()) != 64)) {
		return V8Exception("MakeKeypairFrom512 requires a 64 byte buffer");
	}
	Handle<Object> privateKey = args[0]->ToObject();
	unsigned char* privateKeyData = (unsigned char*)Buffer::Data(privateKey);
	Buffer* publicKey = Buffer::New(32);
	unsigned char* publicKeyData = (unsigned char*)Buffer::Data(publicKey);
	MakeKeypairFromPrivateKey(privateKeyData, publicKeyData);
	Local<Object> result = Object::New();
	result->Set(String::NewSymbol("publicKey"), Local<Object>::New(publicKey->handle_));
	result->Set(String::NewSymbol("privateKey"), privateKey);
	return scope.Close(result);
}

/**
 * Sign(Buffer message, Buffer hash)
 * Sign(Buffer message, Object keyPair)
 * message: the message to be signed
 * hash: 64 byte buffer to make a keypair
 * keyPair: the object from one of the MakeKeypair functions
 * returns: the signature as a Buffer
 **/
Handle<Value> Sign(const Arguments& args) {
	HandleScope scope;
	if ((args.Length() < 2) || (!Buffer::HasInstance(args[0]->ToObject()))) {
		return V8Exception("Sign requires (Buffer, {Buffer | keyPair object})");
	}
	unsigned char* privateKey;
	unsigned char* publicKey;
	if (Buffer::HasInstance(args[1])) {
		unsigned char* hash = (unsigned char*)Buffer::Data(args[1]->ToObject());
		unsigned char publicKeyData[32];
		MakeKeypairFromPrivateKey(hash, publicKeyData);
		privateKey = hash;
		publicKey = publicKeyData;
	} else if (args[1]->IsObject()) {
		Handle<Object> privateKeyBuffer = args[1]->ToObject()->Get(String::New("privateKey"))->ToObject();
		Handle<Object> publicKeyBuffer = args[1]->ToObject()->Get(String::New("publicKey"))->ToObject();
		if ((!Buffer::HasInstance(privateKeyBuffer)) || (!Buffer::HasInstance(publicKeyBuffer))) {
			return V8Exception("Sign requires (Buffer, {Buffer | keyPair object})");
		}
		privateKey = (unsigned char*)Buffer::Data(privateKeyBuffer);
		publicKey = (unsigned char*)Buffer::Data(publicKeyBuffer);
	} else {
		return V8Exception("Sign requires (Buffer, {Buffer | keyPair object})");
	}
	Handle<Object> message = args[0]->ToObject();
	const unsigned char* messageData = (unsigned char*)Buffer::Data(message);
	size_t messageLen = Buffer::Length(message);
	Buffer* signature = Buffer::New(64);
	unsigned char* signatureData = (unsigned char*)Buffer::Data(signature);
	ed25519_sign(signatureData, messageData, messageLen, publicKey, privateKey);
	return scope.Close(signature->handle_);
}

/**
 * Verify(Buffer message, Buffer signature, Buffer publicKey)
 * message: message the signature is for
 * signature: signature to be verified
 * publicKey: publicKey to the private key that created the signature
 * returns: boolean
 **/
Handle<Value> Verify(const Arguments& args) {
	HandleScope scope;
	if ((args.Length() < 3) || (!Buffer::HasInstance(args[0]->ToObject())) || 
		(!Buffer::HasInstance(args[1]->ToObject())) || (!Buffer::HasInstance(args[2]->ToObject()))) {
		return V8Exception("Verify requires (Buffer, Buffer(64), Buffer(32)");
	}
	Handle<Object> message = args[0]->ToObject();
	Handle<Object> signature = args[1]->ToObject();
	Handle<Object> publicKey = args[2]->ToObject();
	if ((Buffer::Length(signature) != 64) || (Buffer::Length(publicKey) != 32)) {
		return V8Exception("Verify requires (Buffer, Buffer(64), Buffer(32)");
	}

	unsigned char* messageData = (unsigned char*)Buffer::Data(message);
	size_t messageLen = Buffer::Length(message);
	unsigned char* signatureData = (unsigned char*)Buffer::Data(signature);
	unsigned char* publicKeyData = (unsigned char*)Buffer::Data(publicKey);
	return scope.Close(Boolean::New(ed25519_verify(signatureData, messageData, messageLen, publicKeyData)));
}


void InitModule(Handle<Object> exports) {
	exports->Set(String::NewSymbol("MakeKeypairFromSeed"), FunctionTemplate::New(MakeKeypairFromSeed)->GetFunction());
	exports->Set(String::NewSymbol("MakeKeypairFrom512Hash"), FunctionTemplate::New(MakeKeypairFrom512Hash)->GetFunction());
	exports->Set(String::NewSymbol("Sign"), FunctionTemplate::New(Sign)->GetFunction());
	exports->Set(String::NewSymbol("Verify"), FunctionTemplate::New(Verify)->GetFunction());
}

NODE_MODULE(native, InitModule)

