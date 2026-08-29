//! DNS message parsing, bounded by construction.
//!
//! ── ★ THE ONE TRAP THIS MODULE EXISTS TO MAKE UNREPRESENTABLE ──────────
//!
//! DNS names are length-prefixed labels, and RFC 1035 §4.1.4 lets a label be
//! replaced by a POINTER to an earlier offset, so a name can be written once
//! and referenced. A pointer may point anywhere in the message — **including
//! at itself, or at a pointer that points back**.
//!
//! A parser that follows pointers with a `loop` and no bound therefore hangs
//! forever on a 14-byte packet that anyone can send to a resolver's open UDP
//! port. This is not a hypothetical: it is the oldest denial-of-service in DNS, and it is
//! reachable before authentication because there is no authentication.
//!
//! So [`Name::parse`] carries a **jump budget** and every jump must move
//! STRICTLY BACKWARD. Both rules are needed and neither is sufficient alone:
//!
//! - Backward-only alone still admits a chain of N/2 distinct backward jumps
//!   in an N-byte message — legal, terminating, but quadratic.
//! - A budget alone still admits forward jumps, which let a crafted message
//!   walk the parser past the region it validated.
//!
//! Together the parse is O(message length) with a hard ceiling, and a
//! self-referential pointer is rejected by name rather than survived.

/// The hard ceiling on pointer jumps in one name.
///
/// ★ Not a tuning knob. RFC 1035 §2.3.4 caps a name at 255 octets and a label
/// at 63, so a name has at most 128 labels; a jump budget above that cannot
/// admit a name a compliant sender could produce, and a budget below it could
/// reject valid traffic. Chosen from the protocol's own limit, not from taste.
pub const MAX_JUMPS: usize = 128;

/// The longest legal encoded name, RFC 1035 §2.3.4.
pub const MAX_NAME_LEN: usize = 255;

/// The longest legal single label, RFC 1035 §2.3.4.
pub const MAX_LABEL_LEN: usize = 63;

/// Two high bits set marks a compression pointer, RFC 1035 §4.1.4.
const POINTER_MASK: u8 = 0b1100_0000;

/// Everything that can be wrong with a message, named.
///
/// ★ Each variant names WHERE, because a resolver that logs "malformed
/// packet" teaches an operator nothing about whether they are under attack or
/// running a broken client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// Ran off the end of the buffer.
    Truncated { at: usize },
    /// A compression pointer that does not move strictly backward — the
    /// self-reference and forward-jump cases, which are the loop.
    NonDecreasingPointer { from: usize, to: usize },
    /// More jumps than any legal name can need.
    JumpBudgetExhausted,
    /// A label longer than 63 octets.
    LabelTooLong { len: usize },
    /// A name longer than 255 octets.
    NameTooLong,
    /// Fewer than the 12 header octets.
    ShortHeader { len: usize },
    /// A query carrying no question.
    NoQuestion,
}

/// A parsed domain name, lowercased.
///
/// ★ Lowercased at PARSE, not at comparison. DNS names are case-insensitive
/// (RFC 4343), so a table keyed on raw bytes answers `RIO` and misses `rio` —
/// a bug that only shows up for whoever typed the capital. Normalizing at the
/// boundary means no comparison site can forget.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Name(String);

impl Name {
    /// Parse a name starting at `pos`, returning the name and the offset just
    /// past it in the ORIGINAL stream (never past a jump target — the caller
    /// must resume where the pointer was, not where it led).
    ///
    /// # Errors
    /// Every variant of [`WireError`] that a name can produce.
    pub fn parse(buf: &[u8], pos: usize) -> Result<(Self, usize), WireError> {
        let mut labels: Vec<String> = Vec::new();
        let mut at = pos;
        let mut jumps = 0usize;
        // Where the caller resumes: fixed at the FIRST pointer, because after
        // a jump the stream position is meaningless to the caller.
        let mut resume: Option<usize> = None;
        let mut total = 0usize;

        loop {
            let len = *buf.get(at).ok_or(WireError::Truncated { at })?;

            if len & POINTER_MASK == POINTER_MASK {
                let lo = *buf.get(at + 1).ok_or(WireError::Truncated { at: at + 1 })?;
                let target = usize::from(u16::from_be_bytes([len & !POINTER_MASK, lo]));

                // ★ STRICTLY BACKWARD. `>=` and not `>`: a pointer to its own
                // offset is the minimal infinite loop, and it is equality that
                // expresses it.
                if target >= at {
                    return Err(WireError::NonDecreasingPointer { from: at, to: target });
                }
                jumps += 1;
                if jumps > MAX_JUMPS {
                    return Err(WireError::JumpBudgetExhausted);
                }
                if resume.is_none() {
                    resume = Some(at + 2);
                }
                at = target;
                continue;
            }

            if len == 0 {
                let end = resume.unwrap_or(at + 1);
                return Ok((Self(labels.join(".")), end));
            }

            let len = usize::from(len);
            if len > MAX_LABEL_LEN {
                return Err(WireError::LabelTooLong { len });
            }
            total += len + 1;
            if total > MAX_NAME_LEN {
                return Err(WireError::NameTooLong);
            }
            let start = at + 1;
            let bytes = buf
                .get(start..start + len)
                .ok_or(WireError::Truncated { at: start })?;
            labels.push(String::from_utf8_lossy(bytes).to_ascii_lowercase());
            at = start + len;
        }
    }

    /// The name as a lowercase dotted string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Build from a host string, normalizing case and any trailing root dot.
    #[must_use]
    pub fn from_host(s: &str) -> Self {
        Self(s.trim_end_matches('.').to_ascii_lowercase())
    }
}

/// The record types annai answers itself. Anything else forwards.
///
/// ★ A closed enum rather than a `u16`: an unhandled type must be a `Forward`
/// decision the compiler can see us make, not a silent `NXDOMAIN` that tells
/// a client a name does not exist when we simply did not implement its type.
/// Answering "no such name" for an unimplemented QTYPE is the failure mode
/// that breaks mail and service discovery while looking like a working
/// resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QType {
    /// IPv4 host address.
    A,
    /// IPv6 host address.
    Aaaa,
    /// Anything we do not answer locally.
    Other(u16),
}

impl QType {
    #[must_use]
    pub fn from_u16(v: u16) -> Self {
        match v {
            1 => Self::A,
            28 => Self::Aaaa,
            other => Self::Other(other),
        }
    }
}

/// A parsed query: what was asked, and the id to answer under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    /// The transaction id, echoed in the response.
    pub id: u16,
    /// The name asked about.
    pub name: Name,
    /// The record type asked for.
    pub qtype: QType,
}

impl Query {
    /// Parse a query message.
    ///
    /// # Errors
    /// [`WireError::ShortHeader`], [`WireError::NoQuestion`], or any name error.
    pub fn parse(buf: &[u8]) -> Result<Self, WireError> {
        if buf.len() < 12 {
            return Err(WireError::ShortHeader { len: buf.len() });
        }
        let id = u16::from_be_bytes([buf[0], buf[1]]);
        let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
        if qdcount == 0 {
            return Err(WireError::NoQuestion);
        }
        let (name, after) = Name::parse(buf, 12)?;
        let qtype_bytes = buf
            .get(after..after + 2)
            .ok_or(WireError::Truncated { at: after })?;
        let qtype = QType::from_u16(u16::from_be_bytes([qtype_bytes[0], qtype_bytes[1]]));
        Ok(Self { id, name, qtype })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_name(s: &str) -> Vec<u8> {
        let mut v = Vec::new();
        for label in s.split('.') {
            v.push(u8::try_from(label.len()).expect("label fits"));
            v.extend_from_slice(label.as_bytes());
        }
        v.push(0);
        v
    }

    fn query_bytes(name: &str, qtype: u16) -> Vec<u8> {
        let mut v = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        v.extend(encode_name(name));
        v.extend_from_slice(&qtype.to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes());
        v
    }

    #[test]
    fn a_pointer_to_itself_is_refused_rather_than_looping_forever() {
        // THE test this module exists for. Byte 12 is `0xC0 0x0C` — a pointer
        // to offset 12, which is where it lives. A parser with an unbounded
        // `loop` hangs here forever on 14 bytes anyone can send.
        let mut buf = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        buf.extend_from_slice(&[0xC0, 0x0C]);
        assert_eq!(
            Query::parse(&buf),
            Err(WireError::NonDecreasingPointer { from: 12, to: 12 })
        );
    }

    #[test]
    fn a_forward_pointer_is_refused() {
        // Forward jumps let a crafted message walk the parser past whatever
        // the caller validated. Backward-only is half the invariant.
        let mut buf = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        buf.extend_from_slice(&[0xC0, 0x20]);
        assert_eq!(
            Query::parse(&buf),
            Err(WireError::NonDecreasingPointer { from: 12, to: 32 })
        );
    }

    #[test]
    fn a_legal_backward_pointer_still_resolves() {
        // The invariant must not cost the feature: compression is normal
        // traffic, and a resolver that refused it would reject real clients.
        let mut buf = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        buf.extend(encode_name("rio.example.net")); // at 12
        let ptr_at = buf.len();
        buf.extend_from_slice(&[0xC0, 0x0C]); // points back to 12
        buf.extend_from_slice(&1u16.to_be_bytes());
        let (name, end) = Name::parse(&buf, ptr_at).expect("legal pointer");
        assert_eq!(name.as_str(), "rio.example.net");
        // ★ Resume is just past the POINTER, never past the jump target.
        assert_eq!(end, ptr_at + 2);
    }

    #[test]
    fn a_name_is_lowercased_at_the_boundary() {
        // DNS is case-insensitive (RFC 4343). A table keyed on raw bytes
        // answers RIO and misses rio, for whoever typed the capital.
        let q = Query::parse(&query_bytes("RIO.Example.NET", 1)).expect("parse");
        assert_eq!(q.name.as_str(), "rio.example.net");
        assert_eq!(q.name, Name::from_host("rio.example.net."));
    }

    #[test]
    fn an_over_long_label_is_refused_by_length() {
        let mut buf = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        buf.push(64); // one over the RFC limit
        buf.extend(std::iter::repeat_n(b'a', 64));
        buf.push(0);
        assert_eq!(Query::parse(&buf), Err(WireError::LabelTooLong { len: 64 }));
    }

    #[test]
    fn a_truncated_message_names_where_it_ran_out() {
        assert_eq!(
            Query::parse(&[0x12, 0x34]),
            Err(WireError::ShortHeader { len: 2 })
        );
    }

    #[test]
    fn a_query_with_no_question_is_refused() {
        let buf = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0];
        assert_eq!(Query::parse(&buf), Err(WireError::NoQuestion));
    }

    #[test]
    fn an_unimplemented_qtype_is_named_not_folded_into_a_or_aaaa() {
        // MX = 15. It must arrive as Other(15) so the decision layer can
        // FORWARD it. Folding it in would answer NXDOMAIN for mail.
        let q = Query::parse(&query_bytes("example.com", 15)).expect("parse");
        assert_eq!(q.qtype, QType::Other(15));
        assert_eq!(
            Query::parse(&query_bytes("rio", 1)).expect("parse").qtype,
            QType::A
        );
        assert_eq!(
            Query::parse(&query_bytes("rio", 28)).expect("parse").qtype,
            QType::Aaaa
        );
    }

    #[test]
    fn the_id_is_preserved_for_the_response() {
        assert_eq!(Query::parse(&query_bytes("rio", 1)).expect("parse").id, 0x1234);
    }
}

// ── RESPONSE ENCODING ──────────────────────────────────────────────────

/// How long a client may cache an answer annai gave from its own table.
///
/// ★ 30 seconds, and the number is derived rather than chosen: the fleet
/// registry changes on a rebuild, and a cached fleet name that outlives the
/// rebuild that moved it is a wrong answer nothing can retract. Short enough
/// that a moved node converges within a poll, long enough that a shell loop
/// does not re-query per command.
pub const LOCAL_TTL: u32 = 30;

/// Encode a response to `q` carrying `addrs`.
///
/// ★ The question is echoed and the answer NAMES it by compression pointer to
/// offset 12 — the standard `0xC00C`. That is a BACKWARD pointer, which is why
/// [`Name::parse`]'s strictly-backward rule does not reject our own output;
/// a resolver whose invariant refused its own replies would be self-defeating,
/// and this is the test that proves it does not.
#[must_use]
pub fn encode_response(q: &Query, addrs: &[std::net::IpAddr], recursion_desired: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&q.id.to_be_bytes());

    // QR=1 (response), RD mirrored from the query, RA=1 (we do recurse, via
    // the upstream). AA stays 0: annai is authoritative for NOTHING, and
    // claiming otherwise is the same lie `Decision` has no variant for.
    let flags: u16 = 0x8000 | u16::from(recursion_desired) << 8 | 0x0080;
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    let ancount = u16::try_from(addrs.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&ancount.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    for label in q.name.as_str().split('.') {
        out.push(u8::try_from(label.len()).unwrap_or(0));
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    let qtype: u16 = match q.qtype {
        QType::A => 1,
        QType::Aaaa => 28,
        QType::Other(v) => v,
    };
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN

    for addr in addrs {
        out.extend_from_slice(&[0xC0, 0x0C]); // name → the question, backward
        match addr {
            std::net::IpAddr::V4(v4) => {
                out.extend_from_slice(&1u16.to_be_bytes());
                out.extend_from_slice(&1u16.to_be_bytes());
                out.extend_from_slice(&LOCAL_TTL.to_be_bytes());
                out.extend_from_slice(&4u16.to_be_bytes());
                out.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                out.extend_from_slice(&28u16.to_be_bytes());
                out.extend_from_slice(&1u16.to_be_bytes());
                out.extend_from_slice(&LOCAL_TTL.to_be_bytes());
                out.extend_from_slice(&16u16.to_be_bytes());
                out.extend_from_slice(&v6.octets());
            }
        }
    }
    out
}

#[cfg(test)]
mod response_tests {
    use super::*;

    fn q(name: &str, qtype: QType) -> Query {
        Query { id: 0xBEEF, name: Name::from_host(name), qtype }
    }

    #[test]
    fn our_own_response_parses_under_our_own_pointer_rule() {
        // ★ The self-consistency test. `0xC00C` is a compression pointer, and
        // the parser refuses non-backward ones — a resolver whose invariant
        // rejected its own replies would be self-defeating.
        let addrs = vec!["10.0.0.1".parse().expect("ip")];
        let bytes = encode_response(&q("rio", QType::A), &addrs, true);
        let (name, _) = Name::parse(&bytes, 12).expect("question parses");
        assert_eq!(name.as_str(), "rio");
        // and the answer's own name field is a legal backward pointer
        let ptr_at = bytes.len() - 4 - 2 - 4 - 2 - 2 - 2;
        let (answer_name, _) = Name::parse(&bytes, ptr_at).expect("answer name parses");
        assert_eq!(answer_name.as_str(), "rio");
    }

    #[test]
    fn the_authoritative_bit_is_never_set() {
        // annai is authoritative for nothing. Setting AA is the wire-level
        // form of the lie `Decision` has no variant for.
        let addrs = vec!["10.0.0.1".parse().expect("ip")];
        let bytes = encode_response(&q("rio", QType::A), &addrs, true);
        let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
        assert_eq!(flags & 0x0400, 0, "AA bit set");
        assert_eq!(flags & 0x8000, 0x8000, "QR bit not set");
    }

    #[test]
    fn the_id_and_question_are_echoed() {
        let addrs = vec!["10.0.0.1".parse().expect("ip")];
        let bytes = encode_response(&q("rio", QType::A), &addrs, true);
        assert_eq!(u16::from_be_bytes([bytes[0], bytes[1]]), 0xBEEF);
        assert_eq!(u16::from_be_bytes([bytes[4], bytes[5]]), 1, "QDCOUNT");
        assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 1, "ANCOUNT");
    }

    #[test]
    fn recursion_desired_is_mirrored_not_invented() {
        let addrs = vec!["10.0.0.1".parse().expect("ip")];
        let with = encode_response(&q("rio", QType::A), &addrs, true);
        let without = encode_response(&q("rio", QType::A), &addrs, false);
        assert_eq!(u16::from_be_bytes([with[2], with[3]]) & 0x0100, 0x0100);
        assert_eq!(u16::from_be_bytes([without[2], without[3]]) & 0x0100, 0);
    }

    #[test]
    fn an_ipv6_answer_carries_sixteen_octets() {
        let addrs = vec!["fd00::1".parse().expect("ip")];
        let bytes = encode_response(&q("v6", QType::Aaaa), &addrs, true);
        assert_eq!(bytes[bytes.len() - 18..bytes.len() - 16], 16u16.to_be_bytes());
        assert_eq!(bytes.len() - 16, bytes.len() - 16);
    }
}
