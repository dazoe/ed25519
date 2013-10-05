var crypto = require('crypto');
var ed25519 = require('./');

/*
	First lets make some keypairs.
*/

// Alice likes to be random, and remembers that the MakeKeypairFromSeed function takes a 32 byte buffer
var aliceKeypair = ed25519.MakeKeypairFromSeed(crypto.randomBytes(32));

// Bob thinks the nsa has their fingers in the random number generator so decides to use a password.
// Charlie told Bob that sha512 rocks. So he decides to use the MakeKeypairFrom512Hash function that takes a 64 byte buffer
var bobsPassword = 'I like the cute monkeys!';
var hash = crypto.createHash('sha512').update(bobsPassword).digest(); //returns a buffer
var bobKeypair = ed25519.MakeKeypairFrom512Hash(hash);


/*
	Now some messages
*/
var message = 'Hi Bob, How are your pet monkeys doing? What were their names again? -Alice';
var signature = ed25519.Sign(new Buffer(message, 'utf8'), aliceKeypair); //Using Sign(Buffer, Keypair object)
// or
signature = ed25519.Sign(new Buffer(message, 'utf8'), aliceKeypair.privateKey); //Using Sign(Buffer, Buffer)

// Alice sends her message and signature over to bob.

// Bob being a paranoid fellow and a good friend of alice has her public key and checks the signature.
if (ed25519.Verify(new Buffer(message, 'utf8'), signature, aliceKeypair.publicKey)) {
	// Bob trusts the message because the Verify function returned true.
	console.log('Signature valid');
} else {
	// Bob doesn't trust the message becuase the Verify function returned false.
	console.log('Signature NOT valid');
}

// Alice is a very courious gal and notices that there is also a key_exchange.c in the public domain code
// that Dave used from https://github.com/nightcracker/ed25519 and wonders if Dave will add a key exchange
// function to this module.

// Dave replys "Maybe, someday. But for now I just needed an implementation of ED25519 to use for a test
// site I'm working on for testing out SQRL(https://www.grc.com/sqrl/sqrl.htm)."

