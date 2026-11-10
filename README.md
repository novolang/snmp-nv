# snmp-nv

SNMP, the Simple Network Management Protocol, is how a manager reads and
changes the state of a network device. A switch, a printer, an UPS or a
sensor runs an *agent* that keeps a tree of named values; a *manager* asks
for them by name. The protocol is specified in
[RFC 3416](https://www.rfc-editor.org/rfc/rfc3416) (the operations),
[RFC 1157](https://www.rfc-editor.org/rfc/rfc1157) (the first version),
[RFC 3412](https://www.rfc-editor.org/rfc/rfc3412) (the version 3 message)
and [RFC 3414](https://www.rfc-editor.org/rfc/rfc3414) (its security). This
package brings the manager side of SNMP to novo-lang, and its messages are
written in the BER of [asn1-nv](https://novo-lang.org/packages/asn1-nv).

## What it is

Every value an agent holds has a name, an *object identifier* (OID) such as
`1.3.6.1.2.1.1.1.0`, which is `sysDescr.0`, the text a device calls itself.
A manager sends a request that names values; the agent answers with a
*Response* that pairs each name with a value. The pair is a *variable
binding*. The operations are Get (read these names), GetNext (read the name
after this one), GetBulk (read several names after this one), Set (write
these names) and, from the agent, Trap and Inform (a notice that something
happened).

There are three versions on the wire. Version 1 (1990) and version 2c (1996)
put a *community string* in each message, a password sent in the clear.
Version 3 (2002) replaces the community with the User-based Security Model:
a user name, an optional digest that proves who sent the message and that it
was not changed, and optional encryption of the request itself.

The package has no socket and no clock. A program that uses it owns the UDP
socket, or whatever carries a datagram, and the timer. Three things follow.

**Messages are built into a buffer and read in place.** A datagram is a
`Vec[u8; 1472]` in the caller's frame, an object identifier is 24 arcs held
inline, and a PDU is up to 8 variable bindings. A value that is a run of
bytes, such as `sysDescr.0`, is not copied: the binding records where the
bytes are in the datagram. Nothing is allocated, so a message can be built
and read on a microcontroller with no heap.

**An exchange is a step.** An `SnmpSession` is a value the caller holds in a
`var`. `request`, `walk` or `discover` builds the first datagram. A datagram
that arrives goes to `on_datagram`, and time that passes goes to `tick`. The
session keeps the request-id, counts the sends, and carries a walk from one
request to the next.

**Cryptography is separate.** The version 3 keys, digests and ciphers take
`Bytes` and use a hash library, which a device without a heap cannot, so
they are three modules the embedded build leaves out. They work on the same
datagram buffers.

## Install

```
novo pkg add snmp-nv
```

## Example

This reads `sysDescr.0` from an agent, with the agent played by the other
half of the program so that it runs anywhere. On a device the two buffers are
the datagrams the UDP stack hands over and takes.

```novo
use snmpber
use snmpoid
use snmppdu
use snmpsession
use snmptext

fn main() [io]
    var s = snmpsession.session_new(snmppdu.SNMP_V2C, "public", 1)

    // 1. Ask for sysDescr.0. The session builds the whole datagram.
    var name = snmpoid.oid_empty()
    let _n = snmpoid.oid_parse(var name, "1.3.6.1.2.1.1.1.0")
    var ask = snmppdu.pdu_new(snmppdu.SNMP_PDU_GET, 0)
    let _a = snmppdu.add_null(var ask, var name)
    var pool: snmpber.SnmpBuf = Vec.new()
    var out: snmpber.SnmpBuf = Vec.new()
    let _r = snmpsession.request(var s, var ask, var pool, var out)
    println("request: ${out.len()} bytes")   // request: 40 bytes

    // 2. The agent answers with a Response carrying a string.
    var reply = snmppdu.pdu_new(snmppdu.SNMP_PDU_RESPONSE, 1)
    var text: snmpber.SnmpBuf = Vec.new()
    let off = snmppdu.pool_add_str(var text, "Linux gateway")
    let _v = snmppdu.add_span(var reply, var name, snmppdu.SNMP_V_OCTETS, off, 13)
    var datagram: snmpber.SnmpBuf = Vec.new()
    let _e = snmppdu.msg_encode(var datagram, snmppdu.SNMP_V2C, "public", var reply, var text)

    // 3. The session reads it, and the caller reads the value out of it.
    var got = snmppdu.pdu_new(0, 0)
    var next: snmpber.SnmpBuf = Vec.new()
    let step = snmpsession.on_datagram(var s, var datagram, var got, var next)
    println("done: ${step.done}, ${snmptext.oid_text(var got.vbs[0].oid)} = ${snmptext.value_text(var datagram, got.vbs[0])}")
    // done: true, 1.3.6.1.2.1.1.1.0 = Linux gateway
```

Build and test with `novo pkg build` and `novo test tests`.

## What the package contains

| Module | Contents |
| --- | --- |
| `snmperr` | The refusals a message can meet as integers, their sentences, and the error-status codes of RFC 3416 with their names. |
| `snmpber` | The buffer, the BER tags SNMP uses, integers of both kinds in their shortest form, a constructed value closed after its contents, and the reading of a header at an offset. |
| `snmpoid` | Object identifiers: parsing the dotted form, comparing in GetNext order, prefixes, and the packing of the first two arcs. |
| `snmppdu` | The PDUs of RFC 3416, the variable bindings with the SMIv2 types and the three exceptions, the v1 and v2c messages, and the v1 Trap-PDU. |
| `snmpv3` | The v3 message, the security parameters of RFC 3414 section 2.4, the scoped PDU, the engine discovery message and the time window. |
| `snmpsession` | A manager's request, a walk and engine discovery as a step: request-ids, retries and the end of a walk. |
| `snmpusm` | Host module. Key localisation, the digest of five authentication protocols, DES and AES-128 privacy, and opening and closing a v3 message. |
| `snmpdes` | Host module. DES and its cipher block chaining mode. |
| `snmptext` | Host module. Object identifiers and values as text. |

Every `pub` declaration is documented where it is declared, and
[the package's page](https://novo-lang.org/packages/snmp-nv) is that
reference.

## How to choose an entry point

**A program that polls an agent uses `snmpsession`.** It builds the request,
reads the answer, and says when to send again. `request` takes any request
PDU, and `walk` is a subtree with one call.

**A program that sends a trap or an agent that answers uses `snmppdu`
directly.** `msg_encode`, `msg_decode` and `pdu_decode` are the whole message
codec, and `trap1_encode` builds the version 1 Trap.

**A program that needs SNMPv3 with a digest uses `snmpsession` and `snmpusm`
together.** The session builds the message with the authentication parameters
as zeros. `snmpusm.protect` encrypts it if the user has a privacy protocol and
writes the digest. A datagram that arrives goes through `snmpusm.unprotect`
before the session reads it.

## The rules a user needs

1. **A value that is bytes is a span.** An OCTET STRING, an Opaque and the
   contents of an OBJECT IDENTIFIER are held as an offset and a length. When
   a PDU is read they point into the datagram, which the caller keeps until it
   has taken the values. When one is built they point into a pool the caller
   fills with `pool_add_str` or `pool_add_oid`.
2. **A Counter64 can be negative.** It is a 64-bit unsigned number held in
   an `Int`, so one of 2^63 or more reads as a negative number with the same
   bits. `snmptext.value_text` prints it unsigned.
3. **An error-status is an answer.** A Response with `noSuchName` or
   `notWritable` completes the request, and `status` and `index` say what
   happened. A failure of the session is a timeout, a walk that does not
   advance, a Report, or a time window.
4. **A retry keeps the request-id.** After a wait with no answer the session
   asks for the same datagram again, so the caller keeps it, and an answer to
   the first send still matches.
5. **A walk ends at the edge of its subtree.** It stops at the first name
   outside the root, at `endOfMibView`, or, in version 1, when the agent
   answers `noSuchName`. A name that does not sort after the one before ends
   it with `SNMP_FAIL_NOT_INCREASING`.
6. **Limits.** An identifier holds 24 arcs (the RFC allows 128), a PDU holds
   8 bindings, a datagram is 1472 bytes, and a community string, an engine ID
   and a user name are at most 32 bytes. A message that exceeds one is
   refused with a named error.
7. **A community string is not a secret.** It is sent in the clear and any
   host on the path can read it. Use version 3 where the data matters.
8. **An SNMPv3 manager must know the agent's engine ID.** `discover` finds
   it. The engine's boots and time are kept, and an authenticated message
   more than 150 seconds behind them is refused (RFC 3414 section 3.2).
9. **The digest covers the whole message.** The authentication parameters hold
   zeros while it is computed, and `snmpusm.protect` writes it in place. A
   message is checked in constant time.
10. **MD5, SHA-1 and DES are here because the standard names them.** A new
    deployment uses `USM_AUTH_SHA256` or longer and `USM_PRIV_AES128`.
11. **A v1 message cannot carry a v2 PDU.** GetBulk, Inform, SNMPv2-Trap and
    Report are refused in a message of version 1 (RFC 3584 section 3.1).

## Running on a microcontroller

These modules build for a microcontroller with no heap allocator: `snmperr`,
`snmpber`, `snmpoid`, `snmppdu`, `snmpv3` and `snmpsession`. They use the
identifier and length octets of `asn1tag`, the one module of asn1-nv that
does the same, and no other package. The modules that need `Bytes` and a hash
(`snmpusm`, `snmpdes`, `snmptext`) are named in the manifest as the package's
host modules and are not part of the build for a device. The registry shows
the tier of the modules that pass, not of the package, so it lists the six.

`tests/embedded_probe.nv` is a firmware program that runs six checks: a Get
and its answer, a walk of three objects with GetNext, a retry and a timeout,
a version 1 trap written and read back, the engine discovery message with
the time window, and the sentences of the error codes. It is compiled for a
Cortex-M as part of this package's checks, so the claim is built rather than
asserted. Under QEMU it prints `PASS: snmp-embedded`.

```
novo build --target=nrf52-qemu tests/embedded_probe.nv
```

The image is 45,164 bytes of flash and 520 bytes of static RAM, and that
includes the runtime and the board's startup code. Of the flash, 30,972 bytes
are the program (the six modules and the probe), 5,602 the runtime, 4,564
libgcc and 4,026 tables and constants. The sizes of the values the probe
holds in its frame are:

| Value | Bytes |
| --- | ---: |
| A datagram, `Vec[u8; 1472]` | 1,480 |
| A PDU of eight bindings, `SnmpPdu` | 1,128 |
| A binding, `SnmpVarbind` | 136 |
| An object identifier, `SnmpOid` | 104 |
| A session, `SnmpSession` | 640 |
| The v3 security parameters, `SnmpUsm` | 168 |

A manager that polls one value at a time keeps one session, one PDU, a
datagram to send and a datagram to receive: about 4.7 KB of frame, and none
of the heap. A device that wants less can build with smaller constants:
`SNMP_MSG_MAX`, `SNMP_VARBINDS_MAX` and `SNMP_OID_MAX` are the three sizes.

## What is not included

- **Sockets and timers.** The caller moves the datagrams and says how much
  time passed.
- **An agent.** The package reads requests and writes responses, which an
  agent needs, but it has no MIB tree, no access control (RFC 3415) and no
  notification originator beyond the v1 Trap.
- **MIB parsing.** There is no SMI module compiler and no symbolic names.
  Object identifiers are numbers or dotted text.
- **SHA-224.** `usmHMAC128SHA224AuthProtocol` of RFC 7860 is not implemented,
  because the hash library has no SHA-224.
- **AES-192 and AES-256 privacy.** They are not in RFC 3826.
- **Key change.** The `keyChange` of RFC 3414 section 2.8 is not implemented.
- **The v2c and v3 Trap sending for an agent, Inform acknowledgement and
  proxy forwarding.** The PDUs are written and read; the exchanges are not
  modelled.
- **Messages over TCP, DTLS or SSH.** RFC 6353 and RFC 5592 carry SNMP over a
  secure transport; this package writes the message only.
- **Bindings over 8 per PDU and identifiers over 24 arcs.** See rule 6.

## Related packages

- [asn1-nv](https://novo-lang.org/packages/asn1-nv) is the BER the messages
  are written in. This package uses its identifier and length arithmetic.
- [crypto-nv](https://novo-lang.org/packages/crypto-nv) is the hashes, HMAC
  and AES that `snmpusm` uses.
- [dns-codec-nv](https://novo-lang.org/packages/dns-codec-nv) and
  [tftp-nv](https://novo-lang.org/packages/tftp-nv) are two more datagram
  protocols written as a step.

## Tests

The suite is six files under `tests/`. What they assert comes from the RFCs
and from independent implementations, not from this code.

`tests/snmp_ber_tests.nv` holds the integer and length encodings and the
object identifiers to bytes worked out by hand from X.690, including the
example of section 8.19.5 that catches a first arc divided by 40.

`tests/snmp_pdu_tests.nv` holds a version 2c GetRequest, a Response with a
string and a version 1 Trap byte by byte, with the length of every
constructed value worked out in the comment, each SMIv2 type and exception,
and every way a PDU, a binding, a message or a trap can be refused.

`tests/snmp_v3_tests.nv` holds the engine discovery request and a message
with the security parameters of RFC 3414 appendix A.4 byte by byte, and the
time window of section 3.2. Appendix A.4 prints lengths that do not agree
with its own octets, so the vector keeps its field values and works the
lengths out.

`tests/snmp_session_tests.nv` plays the agent by hand: a Get, a Set and a
GetBulk, ignored datagrams, retries, a walk with GetBulk and with GetNext, a
walk that does not advance, engine discovery and the Reports of
section 3.2.

`tests/snmp_usm_tests.nv` holds the key-localisation vectors of RFC 3414
appendix A.3.1 and A.3.2 with their intermediate keys, and the localised key
of A.5.2. The SHA-2 keys, the five digests and the AES block were computed
with Python's `hashlib`, `hmac` and `cryptography`, which share no code with
this package. DES is checked against FIPS 81 and AES against NIST SP 800-38A.
A message of every security level is protected and opened again.

`tests/snmp_text_tests.nv` holds the text of each kind of value.

`tests/embedded_probe.nv` is the microcontroller program above.

No captured SNMP datagram from a real device is among the vectors. A capture
to cite would be a useful addition.

`bash tests/coverage.sh` merges the coverage of the suites and reports the
lines of `src/`.

## Licence

Apache-2.0. See `LICENSE`.
