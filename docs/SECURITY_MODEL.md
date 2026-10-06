# HAEP — Security Model

## 1. Threat model

The initial threat model is primarily a hostile or compromised participant on
the same local network.

The prototype is not intended to solve every nation-state or enterprise-PKI
threat.

The design therefore prioritizes strong identity, explicit trust establishment,
authorization enforcement and message integrity without introducing excessive
infrastructure.

## 2. Identity

HAEP uses Ed25519 identities in the current implementation.

A participant has:

- private key;
- public key;
- fingerprint derived from the public key.

The private key must never be transmitted or committed to Git.

The fingerprint identifies the cryptographic identity, not a mutable name or
network address.

## 3. Discovery

mDNS may be used as a candidate discovery mechanism.

Discovery does not grant trust.

An unknown device found on the LAN remains untrusted until pairing succeeds.

## 4. Pairing

A new controller must not become trusted merely because it can produce a valid
signature.

The current TEST-0001 flow is:

```text
unknown controller
      |
      v
valid signed pairing request
      |
      v
pairing window?
   no | yes
      | 
   DENIED       PAIRING_PENDING
                     |
                     v
              explicit OOB approval
                     |
                     v
              request TTL valid?
                 no | yes
                    |
                 DENIED       PAIRED
```

Replay protection applies to pairing `request_id` and `nonce`.

Revoked agents cannot be paired.

## 5. Authorization

Pairing does not imply authorization to perform every capability.

Authorization is separately evaluated by the Policy Authority.

The resulting AuthorizationAssertion is signed and bound to the request.

Important bindings include:

- controller;
- Agent;
- capability;
- resource;
- request_id;
- nonce;
- time window;
- parameter hash.

The Agent verifies the assertion and its scope before execution.

## 6. Default security posture

The intended posture is closed-by-default:

- unknown controller -> reject;
- invalid signature -> reject;
- invalid authorization assertion -> reject;
- scope mismatch -> reject;
- expired request -> reject;
- replay -> reject;
- revoked trust -> reject;
- unauthorized capability/resource -> reject.

## 7. Known prototype limitations

The following remain explicit engineering items:

- Policy Authority public-key bootstrap must have a trusted provisioning path.
- Replay state in TEST-0001 is currently process-local and therefore not a
  complete restart-resistant production design.
- Private-key files in the prototype use simple local storage and are not a
  production hardware-backed key-management solution.
- A signed `confirmation` field is not by itself a complete interactive user
  confirmation protocol.

These limitations should be resolved through explicit design decisions, not
implicit assumptions.

## 8. Secrets

Never commit:

- private keys;
- access tokens;
- passwords;
- credentials;
- production secrets;
- `.env` files containing secrets.

Temporary test keys must be generated during tests or otherwise excluded from
version control.
