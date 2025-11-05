# SSH over Velocity (Design Summary)

This document summarises the planned approach for transporting SSH over the
Velocity protocol. The goal is to provide administrators with a migration path
that preserves existing SSH workflows while upgrading the underlying transport
to post-quantum secure primitives.

## Objectives

- Maintain user-facing SSH semantics (authentication methods, agent forwarding,
  subsystem support) while replacing TCP with Velocity streams.
- Provide hybrid (classical + Dilithium) host certificates that integrate with
  existing OpenSSH trust stores.
- Offer a reversible deployment path: Velocity can run alongside traditional
  SSH until operators are confident in the new transport.

## Components

1. **`vsh-proxy` (client-side)**
   - Executed via OpenSSH `ProxyCommand`.
   - Performs the Velocity handshake, negotiates the highest mutually supported
     security profile, and establishes a dedicated Velocity stream for SSH
     traffic.
   - Forwards bytes between the local SSH client and the remote Velocity server.

2. **`vshd` (server-side)**
   - Accepts Velocity connections, validates hybrid certificates, and passes the
     resulting authenticated stream to the local `sshd` process (or libssh based
     server) using its subsystem API.
   - Emits structured logs capturing negotiated profile, ALPN, client identity,
     and replay decisions for auditing purposes.

3. **Certificate Bridge**
   - Velocity CA issues hybrid certificates with both classical and Dilithium
     signatures.
   - A conversion tool generates SSH host certificates containing the same
     public key material plus a Dilithium signature extension.
   - Clients verify both signatures; downgrade attempts trigger warnings or are
     rejected based on policy.

## Migration Phases

1. **Parallel Deployment**
   - Run Velocity on UDP/443 (or a staging port) alongside traditional SSH on
     TCP/22.
   - Encourage early adopters to use `vsh-proxy` via targeted host aliases in
     `~/.ssh/config`.

2. **Progressive Enforcement**
   - Use `Match` blocks in `sshd_config` to require Velocity transport for
     specific users or groups.
   - Instrument metrics to monitor handshake outcomes, downgrade rates, and
     replay protection events.

3. **Full Cutover**
   - Disable direct TCP/22 access once Velocity transport proves stable.
   - Maintain fallback procedures in documentation for emergency downgrades.

## Replay Protection and 0-RTT

Velocity session tickets include replay windows and optional client address
binding. For SSH, it is RECOMMENDED to disable 0-RTT during the initial rollout
or restrict it to idempotent operations (e.g., server banners) until robust
replay tracking is in place.

## Operational Checklist

- [ ] Issue hybrid certificates from the Velocity CA and install them on the
      target hosts.
- [ ] Deploy `vshd` alongside `sshd`, ensuring logs are integrated with existing
      SIEM tooling.
- [ ] Update client configurations to invoke `vsh-proxy` for pilot hosts.
- [ ] Document rollback steps and maintain a playbook for falling back to TCP.

As the implementation matures, expand this document with configuration samples,
performance considerations, and troubleshooting guidance.
