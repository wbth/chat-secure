Summary of Key Components Involved in Message Sending:
User Authentication: Verify user credentials and decrypt the private key.
X3DH Key Exchange: Establishing a shared secret between the sender and recipient.
AES-GCM Encryption: Encrypting the message using the shared secret.
Database: Storing encrypted messages in the database.
Decryption (By Recipient): Using the shared secret derived from the X3DH exchange to decrypt the message.
Display: Showing the decrypted message to the user.
This system ensures secure communication using cryptographic solid techniques like X3DH, AES-GCM, and EdDSA. It also handles session management with Flask and ensures the integrity and confidentiality of messages exchanged between users.

1. User Login
Password Verification: The password entered is compared with the hashed password stored in the database using the Argon2 password hashing algorithm. If the password matches, the session is created for that user, and their private key is decrypted.

2. Database Setup
Database Connection: The SQLite database stores user data (including usernames, password hashes, and public/private keys) and messages. You can set up a database connection when needed.

3. Key Exchange and Shared Secret Generation (X3DH)
X3DH Key Exchange: When a user sends a message to another user, the system performs the X3DH key exchange to establish a shared secret between the sender and the recipient.
The sender’s private and recipient’s keys are used in the key exchange process.
The resulting shared secret will be used to encrypt the message.

4. Encryption of Message (AES-GCM)
Message Encryption: Once the shared secret is established, the sender uses it to encrypt the message using AES-GCM encryption.
The shared secret is truncated to 32 bytes (AES-256).
A nonce (random number) is generated to ensure that the ciphertext is different even for the same message.
The message is then encrypted, and the nonce, tag, and ciphertext are combined and base64-encoded to send to the recipient.

5. Sending the Message
Insert Encrypted Message into Database: The encrypted message and the recipient's username are inserted into the messages table in the database.

6. Message Retrieval and Decryption (By Recipient)
Message Fetching: The recipient’s messages are retrieved from the database, where the message is stored in its encrypted form.
Decryption: The recipient will use their private and sender keys for each message to perform the X3DH key exchange and derive the shared secret.
The shared secret is used to decrypt the message using AES-GCM.

7. Decrypted Message Display
Displaying the Decrypted Message: Once the message is successfully decrypted, it is shown in the chat interface.


