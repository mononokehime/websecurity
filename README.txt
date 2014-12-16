Goals
===========
1. To reduce the risk on man-in-the-middle attack.
2. To perform data encryption on all REST messages

Assumptions
===========
1. All requests/responses will be encrypted and MAC'd
2. SSL will continue to be used.

Overview
===========
1. Calculates a Hash based Message Authentication Code (HMAC) using a session MAC key in order to verify the message integrity and authenticity.
2. Request/Response is encrypted with a session encryption key

Key Exchange
===========
1. An RSA public/private key is used to protext data during the key exchange process. The public key will be built in to the client app. The private key will be in the java keystore.
2. There is a Session MAC key (SMK) and a Session Encryption Key (SEK). Eack key is made of a server and client component, these are then combined to form the key.

HMAC
===========
HMAC is a mechanism for calculating a message authentication code using a hash function in combination with a secret key. The result is used to verify the integrity and authenticity of a message
Both the client and server should perform verification.
The MAC is passed as a header between server and client. It is a Base64 encoded set of SHA256 hash algorithms comprised of a number of values including
URL, canonicalised headers and content body (request and response)

Content Encryption
===========
The request and response are encrypted using the SEK. The content is encrypted and then HMAC is applied as per:
http://crypto.stackexchange.com/questions/202/should-we-mac-then-encrypt-or-encrypt-then-mac
This means messages can be rejected before expensive decryption operations occur.

Implementation
===========
1. Some of the implementation details have been removed from the code.
2. A SecurityFilter is set up which captures all requests.
3. Request and Response Wrappers are used for encryption/decryption operations.
4. There is an option to turn encryption/dcryption options off via JVM parameters


