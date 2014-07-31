SigAnima
========

SigAnima is an JavaCard ECDSA signing applet. This applet is based on the javacardsign applet from Wojciech Mostowski (http://sourceforge.net/projects/javacardsign/).

Applet Specifications
---------------------

The current version of the applet and the host library implements the following features: 

+ An ISO7816 ﬁle system for storing PKI ﬁles. The applet support hierarchical ﬁle system including relative to current ﬁle selection or selection by path. Reading of each ﬁle can be user PIN protected.
+ PIN and PUK user authentication: a 4 to 10 characters long PIN code, and a 10 characters long PUK code. The PUK code lets the user change and unblock a forgotten PIN code.
+ The applet does not support any kind of secure messaging for APDU communication.
+ Signing cryptographic operation with ECC GF(p) curves. The supported key length is up to 320 bit depending on underlying Java Card implementation. Signing (perform security operation command) uses a plain ECDSA signature. No hashes will be calculated before the signing inside the card. The signing function will pad data to sign with leading zero up to the size of the public key if the data is shorter then the public key size. If the data to sign is bigger then the public key, the data will be truncated to the size of the public key. 
The Java Card API involved is SignatureX.ALG_ECDSA_PLAIN which is currently only available in cards with JCOP v2.4.1 R2 or later. The result of the signing operation is the ECDSA signature in the following ASN.1 format.
<pre>
ECDSA-Signature ::= SEQUENCE {
  r  INTEGER,
  s  INTEGER }
</pre>
+ The AID of the applet is chosen to be 0xD2760001324543534947. The applet does not support/provide any FCI information on applet/ﬁle selection. It is recommended that the SigAnima applet is made default selectable on the card.
+ Only during the personalization phase, the on-card key generation is possible. Currently, the applet can generate EC keys up to 320 bits.
+ The applet supports the following standardized EC domain parameters: secp224r1, BrainpoolP224r1, secp256r1, BrainpoolP256r1, BrainpoolP320r1

For more information take a look into included documentation PDF file.
