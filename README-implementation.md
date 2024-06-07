
### How process isolation is designed

The server is divided into a privileged process, `chatpriv`, and unpriviledged chat processes `chatd`.

The client, `chat`, can only communicate with `chatd` after logging in.

All commands requiring elevated privileges are forwarded from `chatd` to `chat`, which then communicates the result back to the `chatd` instance.

### How authentication is performed

- Locking the operating-system shadow file
- Getting the password hash/salt for the UNIX user of the same name from the operating-system shadow file
- Hashing the provided password using the same algorithm and combining with same salt as found in the shadow file via `crypt` function provided by the operating-system.
- Checking if the resulting hash is the same as the UNIX user's hashed+salted password
- Unlocking the operating-system shadow file when succeeded/failed

The user is then authenticated if all of the above is successful.

### How information transmitted in network messages is protected

This program protects information transmitted in network messages using encryption via the tweetnacl library.

When clients first connect, they send their public key to the server.

Each client is shipped with the server's public key.

Nonce values are chosen using the existing `getentropy` function provided by the operating-system.

Tweetnacl is then used to take care of the encryption/decryption for all messages after the client sends its public key to the server.

### How persistently stored information is protected

The only persistent information stored is usernames/passwords through the operating-system.

Usernames are stored in `/etc/shadow` and `/etc/passwd`, which require root access to read/write.

Hashed passwords are stored in `/etc/shadow` which requires root access to read/write. They are salted to guard against dictionary attacks.

Only the `chatpriv` process runs with root privileges. Each active chatter's connection is handled in a separate less privileged process which only has their permissions, so all interaction with these files is handled by `chatpriv`.

