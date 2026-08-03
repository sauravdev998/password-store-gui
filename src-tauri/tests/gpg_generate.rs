//! Key generation against a real `gpg`, a real agent, and a real pinentry.
//!
//! **Ignored, and run by hand:**
//!
//! ```sh
//! cargo test --test gpg_generate -- --ignored --nocapture
//! ```
//!
//! It is ignored for a reason that cannot be engineered away. Generating a key
//! raises a pinentry asking for the new key's passphrase, and answering it is
//! the user's job — that is the whole of Invariant 3. The two ways to make it
//! unattended are `--passphrase` and `--pinentry-mode loopback`, which are
//! exactly what §4 forbids and what ADR-7 exists to keep out. So CI covers the
//! *argument list* in `crypto/gnupg.rs` and this covers the *behaviour*, once,
//! wherever a human is present.
//!
//! It runs against the fixture's throwaway `GNUPGHOME`, so the key it makes is
//! discarded with the temporary directory and never touches the developer's own
//! keyring. Type anything into the prompt — including nothing.
//!
//! Its own `#[test]` binary because `GNUPGHOME` is process-global (see
//! `common`), and because an ignored test sharing a binary with a run one would
//! be one `--ignored` away from racing it.

#![allow(clippy::print_stdout, clippy::print_stderr)]
#![allow(clippy::unwrap_used)]

mod common;

use password_store_gui_lib::crypto::{Gnupg, Gpg};
use password_store_gui_lib::error::Error;

#[test]
#[ignore = "raises a pinentry prompt a human has to answer (Invariant 3, ADR-7)"]
fn generating_a_key_prompts_through_the_agent_and_produces_a_usable_key() {
    let Some(_fixture) = common::GpgFixture::new() else {
        println!("skipping: no gpg on PATH");
        return;
    };
    let gpg = Gnupg::new().unwrap();

    let before = gpg.usable_keys().unwrap().len();

    println!("\n>>> A pinentry window should appear. Enter any passphrase, or cancel to check the other half.\n");
    let key = match gpg.generate_key("Phase Seven", "phase7@example.invalid") {
        Ok(key) => key,
        Err(Error::KeyGenerationCancelled) => {
            // The other half of ADR-7's probe, and worth reaching deliberately:
            // a dismissed prompt must leave the keyring exactly as it was, so
            // the wizard can offer the button again rather than having to
            // repair something.
            assert_eq!(
                gpg.usable_keys().unwrap().len(),
                before,
                "a cancelled generation must leave no key behind"
            );
            println!("cancelled: no key was created, which is the documented behaviour");
            return;
        }
        Err(err) => panic!("key generation failed: {err}"),
    };

    // The label proves the user id was assembled and accepted as typed.
    assert_eq!(
        key.label.as_deref(),
        Some("Phase Seven <phase7@example.invalid>")
    );
    // `describe_key` refuses a key with no usable encryption subkey, so getting
    // here at all means `--quick-generate-key`'s defaults produced one that can
    // actually back a store.
    assert!(!key.keys.is_empty());
    assert!(key.usable_here, "the secret half must be on this keyring");

    // And it is offered next time, which is the path onboarding takes for a
    // user who already had a key.
    let offered = gpg.usable_keys().unwrap();
    assert_eq!(offered.len(), before + 1);
    assert!(offered.iter().any(|found| found.id == key.id));

    println!("created and verified: {}", key.id);
}
