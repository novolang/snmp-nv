# Changelog

All notable changes to snmp-nv are recorded here. The format is
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
package follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
with the pre-1.0 rule that a breaking change bumps the MINOR number.

## 0.1.0

The first release.

### Added

- **`snmpber`, `snmpoid`, `snmppdu`**, SNMP messages with no allocation.
  Integers in the shortest form, unsigned values with the leading zero
  octet, constructed values closed after their contents, and a header read at
  an offset, over the identifier and length octets of `asn1tag` from
  asn1-nv. Object identifiers of up to 24 arcs, with the packing of the first
  two arcs and the order GetNext walks. The eight PDUs of RFC 3416 with the
  SMIv2 value types and the three exceptions, the SNMPv1 and SNMPv2c
  messages of RFC 1157 and RFC 3584, and the v1 Trap-PDU.
- **`snmpv3`**, the message of RFC 3412 and the security parameters of
  RFC 3414 section 2.4, the scoped PDU, the engine discovery message
  (section 4) and the time window (section 3.2).
- **`snmpsession`**, a manager's Get, GetNext, GetBulk, Set, walk and engine
  discovery as a step: request-ids, retransmission with the same
  request-id, datagrams that are not the answer ignored, and a walk that
  ends at the subtree, at `endOfMibView`, at v1's `noSuchName`, or fails when
  it does not advance.
- **`snmpusm`, `snmpdes`**, key localisation (RFC 3414 appendix A.2),
  HMAC-MD5-96, HMAC-SHA-96 and the SHA-256, SHA-384 and SHA-512 variants of
  RFC 7860, CBC-DES and the AES-128 cipher feedback mode of RFC 3826, and
  `protect` and `unprotect` over a v3 message. **`snmptext`**, identifiers and
  values as text. These three take `Bytes` and are the package's host
  modules.
- **`tests/embedded_probe.nv`**, a firmware program that runs six checks
  and is built for `--target=nrf52-qemu`. It prints `PASS: snmp-embedded`
  under QEMU. The image is 45,196 bytes of flash and 520 bytes of static RAM.
- Six test suites, with the vectors of RFC 3414 appendix A.3 and A.5.2,
  X.690, FIPS 81 and NIST SP 800-38A, and byte-by-byte messages worked out
  by hand.

### Not included

- MIB parsing and symbolic names.
- SHA-224 (`usmHMAC128SHA224AuthProtocol`), AES-192 and AES-256, and the
  `keyChange` operation.
- An agent: no MIB tree, no access control, no notification originator
  beyond the version 1 Trap.
- Sockets and timers. The caller moves the datagrams and says how much time
  passed.
