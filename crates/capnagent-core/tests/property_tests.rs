//! Property tests for the load-bearing invariants of capnagent-core.
//!
//! These are the security argument expressed as code. If any of them ever
//! flake or fail, the threat model in `docs/DESIGN.md` is broken — do not
//! "fix" the test, fix the implementation.

use capnagent_core::{Capability, Caveat, Issuer, Verifier};
use proptest::prelude::*;

fn build(key: &[u8], id: &str, caveats: &[String]) -> Capability {
    let mut b = Issuer::from_key(key).issue(id);
    for c in caveats {
        b = b.caveat(c.clone());
    }
    b.build()
}

proptest! {
    /// The most basic invariant: an honestly-issued capability verifies
    /// under the same key.
    #[test]
    fn issued_capability_verifies(
        key in prop::collection::vec(any::<u8>(), 16..64),
        id in "[a-zA-Z0-9_\\-]{1,32}",
        caveats in prop::collection::vec("[a-zA-Z0-9 =<>!._\\-]{0,64}", 0..10),
    ) {
        let cap = build(&key, &id, &caveats);
        prop_assert!(Verifier::new(&key).verify(&cap).is_ok());
    }

    /// Anyone holding a capability can attenuate it, and the result still
    /// verifies. This is the "delegation works" half of the macaroon contract.
    #[test]
    fn attenuation_preserves_validity(
        key in prop::collection::vec(any::<u8>(), 16..64),
        id in "[a-zA-Z0-9_\\-]{1,32}",
        initial in prop::collection::vec("[a-zA-Z0-9 =<>!._\\-]{0,64}", 0..5),
        added in prop::collection::vec("[a-zA-Z0-9 =<>!._\\-]{0,64}", 0..5),
    ) {
        let mut cap = build(&key, &id, &initial);
        for c in &added {
            cap = cap.attenuate(c.clone());
        }
        prop_assert!(Verifier::new(&key).verify(&cap).is_ok());
    }

    /// Round-trip: serialize → parse → verify must succeed.
    #[test]
    fn round_trip_serialize_parse_verify(
        key in prop::collection::vec(any::<u8>(), 16..64),
        id in "[a-zA-Z0-9_\\-]{1,32}",
        caveats in prop::collection::vec("[a-zA-Z0-9 =<>!._\\-]{0,64}", 0..5),
    ) {
        let cap = build(&key, &id, &caveats);
        let token = cap.serialize();
        let parsed = Capability::parse(&token).unwrap();
        prop_assert_eq!(&cap, &parsed);
        prop_assert!(Verifier::new(&key).verify(&parsed).is_ok());
    }

    /// Dropping a caveat is the canonical *broaden* attempt. It MUST fail
    /// verification — this is the property the whole project depends on.
    #[test]
    fn dropping_a_caveat_breaks_verification(
        key in prop::collection::vec(any::<u8>(), 16..64),
        id in "[a-zA-Z0-9_\\-]{1,32}",
        caveats in prop::collection::vec("[a-zA-Z0-9 =<>!._\\-]{0,64}", 1..5),
    ) {
        let cap = build(&key, &id, &caveats);
        let mut tampered = cap.clone();
        tampered.caveats.pop();
        prop_assert!(Verifier::new(&key).verify(&tampered).is_err());
    }

    /// Reordering caveats also breaks verification. Order is part of the
    /// signed payload — adversaries must not be able to permute.
    #[test]
    fn reordering_caveats_breaks_verification(
        key in prop::collection::vec(any::<u8>(), 16..64),
        id in "[a-zA-Z0-9_\\-]{1,32}",
        a in "[a-zA-Z0-9 =<>!._\\-]{1,32}",
        b in "[a-zA-Z0-9 =<>!._\\-]{1,32}",
    ) {
        prop_assume!(a != b);
        let cap = build(&key, &id, &[a.clone(), b.clone()]);
        let mut tampered = cap.clone();
        tampered.caveats.swap(0, 1);
        prop_assert!(Verifier::new(&key).verify(&tampered).is_err());
    }

    /// Replacing any caveat with a different predicate breaks verification.
    /// This kills the "swap a tight caveat for a permissive one" attack.
    #[test]
    fn modifying_a_caveat_breaks_verification(
        key in prop::collection::vec(any::<u8>(), 16..64),
        id in "[a-zA-Z0-9_\\-]{1,32}",
        caveats in prop::collection::vec("[a-zA-Z0-9 =<>!._\\-]{1,64}", 1..5),
        replacement in "[a-zA-Z0-9 =<>!._\\-]{1,64}",
        idx in any::<usize>(),
    ) {
        let cap = build(&key, &id, &caveats);
        let i = idx % cap.caveats.len();
        prop_assume!(cap.caveats[i].predicate != replacement);
        let mut tampered = cap.clone();
        tampered.caveats[i] = Caveat::new(replacement);
        prop_assert!(Verifier::new(&key).verify(&tampered).is_err());
    }

    /// Flipping any single bit in the signature breaks verification.
    #[test]
    fn signature_bitflip_breaks_verification(
        key in prop::collection::vec(any::<u8>(), 16..64),
        id in "[a-zA-Z0-9_\\-]{1,32}",
        caveats in prop::collection::vec("[a-zA-Z0-9 =<>!._\\-]{0,64}", 0..3),
        bit_idx in any::<usize>(),
    ) {
        let cap = build(&key, &id, &caveats);
        let mut tampered = cap.clone();
        let total_bits = tampered.signature.len() * 8;
        prop_assume!(total_bits > 0);
        let bi = bit_idx % total_bits;
        tampered.signature[bi / 8] ^= 1 << (bi % 8);
        prop_assert!(Verifier::new(&key).verify(&tampered).is_err());
    }

    /// Two distinct keys must not cross-verify each other's tokens.
    #[test]
    fn capabilities_do_not_cross_verify(
        key_a in prop::collection::vec(any::<u8>(), 16..64),
        key_b in prop::collection::vec(any::<u8>(), 16..64),
        id in "[a-zA-Z0-9_\\-]{1,32}",
    ) {
        prop_assume!(key_a != key_b);
        let cap = Issuer::from_key(&key_a).issue(&id).build();
        prop_assert!(Verifier::new(&key_b).verify(&cap).is_err());
    }

    /// An adversary without the root key cannot forge a capability that
    /// verifies. We model "the adversary" as: pick any identifier, any
    /// caveats, and any signature bytes — verification must reject unless
    /// they happened to guess a valid HMAC chain (vanishingly unlikely).
    #[test]
    fn adversarial_forgery_is_rejected(
        key in prop::collection::vec(any::<u8>(), 16..64),
        id in "[a-zA-Z0-9_\\-]{1,32}",
        caveats in prop::collection::vec("[a-zA-Z0-9 =<>!._\\-]{0,64}", 0..5),
        forged_sig in prop::collection::vec(any::<u8>(), 32..=32),
    ) {
        // Compute what the real signature would be, so we can avoid the
        // (effectively zero-probability) case where the adversary guessed it.
        let real = Issuer::from_key(&key).issue(&id);
        let real = caveats.iter().fold(real, |b, c| b.caveat(c.clone())).build();
        prop_assume!(real.signature != forged_sig);

        let forged = Capability {
            identifier: id,
            caveats: caveats.into_iter().map(Caveat::new).collect(),
            signature: forged_sig,
        };
        prop_assert!(Verifier::new(&key).verify(&forged).is_err());
    }
}
