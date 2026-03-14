# SecureIoT-Protocol

SecureIoT-Protocol is an educational C++ project that demonstrates a lightweight security protocol for IoT device communication. It defends against replay attacks, message tampering, duplicate packets, and unauthorized message injection using nonces, timestamps, hashing, and symmetric encryption.

This project is for learning and portfolio use. The custom hash and XOR-based encryption are intentionally simple and are not production-grade cryptography.

## Protocol Pipeline

Sender pipeline:

1. Create message.
2. Generate a fresh nonce.
3. Attach a timestamp.
4. Compute a keyed hash of `message || nonce || timestamp`.
5. Encrypt the payload using the shared key and packet metadata.
6. Transmit the packet.

Receiver pipeline:

1. Receive packet.
2. Decrypt payload.
3. Verify hash.
4. Validate timestamp freshness.
5. Check nonce uniqueness.
6. Accept or reject.

## Packet Structure

The packet is serialized as:

- Header (clear):
  - `nonce` (8 bytes)
  - `timestamp` (8 bytes, Unix epoch seconds)
- Encrypted payload:
  - `message_len` (4 bytes, big-endian)
  - `message` (`message_len` bytes)
  - `hash` (16 bytes, keyed integrity hash of message + nonce + timestamp)

The header is kept in clear so the receiver can derive the keystream. The hash still binds the header to the payload, so tampering with the header causes verification to fail.

## Security Architecture

- Nonce usage: Each message includes a fresh random nonce. The receiver stores recently seen nonces in a replay cache. If the same nonce appears again within the cache window, the packet is rejected as a replay or duplicate.
- Timestamp validation: Each packet carries a timestamp (seconds since epoch). The receiver checks that the timestamp is within a small allowed window (`kMaxClockSkewSeconds`). This blocks delayed/replayed packets outside the freshness window.
- Hash-based integrity: The sender computes a keyed hash over `message + nonce + timestamp`. After decryption, the receiver recomputes the hash and compares it with the transmitted hash. Any message tampering, nonce changes, or timestamp modification results in a mismatch and the packet is rejected.
- Symmetric encryption: The payload is encrypted using a shared key and per-packet metadata (nonce + timestamp). An attacker without the key cannot generate valid ciphertext, which blocks unauthorized packet injection.

## Replay Protection Details

The `ReplayCache` module stores nonces for a limited time window (TTL) and a maximum number of entries. Old entries are pruned automatically. This prevents:

- Replay attacks: Previously captured packets cannot be re-accepted because their nonce has already been recorded.
- Duplicate packets: Accidental retransmissions are also rejected.

## Modules

- `encryption.cpp` and `encryption.h`: XOR stream encryption with key mixing and bit rotations.
- `hash.cpp` and `hash.h`: Lightweight educational keyed hash for integrity checks.
- `nonce.cpp` and `nonce.h`: Random nonce generation.
- `replay_protection.cpp` and `replay_protection.h`: Replay cache with TTL and max capacity.
- `packet.cpp` and `packet.h`: Packet format definition and serialization.
- `demo_sender.cpp`: Creates and encrypts a secure packet.
- `demo_receiver.cpp`: Decrypts, verifies, and validates a packet.

## How Each Attack Is Prevented

- Replay attacks: Blocked by timestamp freshness checks plus nonce replay cache.
- Message modification: Blocked by the hash comparison after decryption.
- Duplicate packets: Blocked by nonce replay cache.
- Unauthorized injection: Blocked by encryption and keyed hashing, since attackers cannot forge valid ciphertext without the key.

## Build and Run

Build with Makefile:

```bash
make
```

Manual compile:

```bash
c++ -std=c++17 -O2 -o demo_sender demo_sender.cpp encryption.cpp hash.cpp nonce.cpp packet.cpp
c++ -std=c++17 -O2 -o demo_receiver demo_receiver.cpp encryption.cpp hash.cpp replay_protection.cpp packet.cpp
```

Send a packet:

```bash
./demo_sender "humidity=40%" packet.bin
```

Receive and verify:

```bash
./demo_receiver packet.bin
```

Replay demo (processes the same packet twice):

```bash
./demo_receiver packet.bin --replay
```

## Important Notes

- The demo uses a static shared key in `demo_config.h`. In real devices, this must be securely provisioned and rotated.
- The custom hash and XOR encryption are intentionally simple and should be replaced for any real deployment.

## Possible Improvements

- Replace the custom hash with SHA-256.
- Replace the XOR stream cipher with AES (or another standardized AEAD cipher).
- Use HMAC for authenticated integrity in addition to encryption.
