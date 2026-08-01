#!/usr/bin/env bash
#
# Build a throwaway password store and GnuPG home for testing the real app.
#
#   ./scripts/make-fixture-store.sh /tmp/ps-fixture
#   GNUPGHOME=/tmp/ps-fixture/gnupg PASSWORD_STORE_DIR=/tmp/ps-fixture/store \
#     pnpm tauri dev
#
# The key is generated with `%no-protection`, exactly as `src-tauri/tests/common`
# does: no passphrase means no pinentry, so driving the app never blocks on a
# prompt. That is a property of the fixture, not a loophole in Invariant 3 — no
# passphrase is ever passed and `--pinentry-mode` is never set (ADR-4a, F-2).
#
# The contents mirror `src/lib/mockInvoke.ts`, so the stubbed frontend
# (`pnpm dev:mock`) and the real app show the same entries.
#
# Never point this at a directory you care about: it deletes the target first.
set -euo pipefail

BASE="${1:?usage: make-fixture-store.sh <base-dir>}"
export GNUPGHOME="$BASE/gnupg"
STORE="$BASE/store"

rm -rf "$BASE"
mkdir -p "$GNUPGHOME" "$STORE"
# gpg warns loudly about a world-readable home.
chmod 700 "$GNUPGHOME"

cat >"$GNUPGHOME/key-params.txt" <<'EOF'
Key-Type: eddsa
Key-Curve: ed25519
Subkey-Type: ecdh
Subkey-Curve: cv25519
Name-Real: Password Store GUI Test
Name-Email: test@example.invalid
Expire-Date: 0
%no-protection
%commit
EOF
gpg --batch --quiet --generate-key "$GNUPGHOME/key-params.txt"

# A *user id*, not a fingerprint. That is the case `prs-lib`'s find_public_keys
# drops silently (ADR-6, F-8), so the fixture exercises our own encrypt path.
echo 'test@example.invalid' >"$STORE/.gpg-id"

# enc <relative-name>, with the plaintext on stdin.
enc() {
  local out="$STORE/$1.gpg"
  mkdir -p "$(dirname "$out")"
  gpg --batch --yes --quiet --trust-model always \
      --recipient test@example.invalid --encrypt --output "$out"
}

# The otpauth secret is the RFC 6238 test seed, so the code the app shows can be
# checked against any other TOTP implementation.
enc 'Email/gmail.com' <<'EOF'
correct-horse-battery-staple
username: me@example.invalid
url: https://mail.google.com
otpauth://totp/Google:me@example.invalid?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Google
Recovery codes are in the safe.
Second line of notes.
EOF

enc 'Email/work.example' <<'EOF'
just-a-password
EOF

# Repeated keys: the index is a field's identity, so two `token:` lines are the
# case `reveal_field`'s index addressing has to get right.
enc 'Banking/chase' <<'EOF'
tr0ub4dour&3
username: saurav
token: first-token
token: second-token
Call the branch before travelling.
EOF

enc 'Servers/prod/db' <<'EOF'
deep-nested-secret
username: postgres
EOF

enc 'wifi' <<'EOF'
hunter2hunter2
Guest network, rotates monthly.
EOF

# A name the core refuses (F-6 rejects `$`). It must surface as `unsupported`
# rather than vanishing from the tree.
printf 'not really ciphertext' >"$STORE/weird\$name.gpg"

git -C "$STORE" init -q -b main
git -C "$STORE" config user.email test@example.invalid
git -C "$STORE" config user.name 'Password Store GUI Test'
# A developer's global config may sign commits; this GNUPGHOME has no such key.
git -C "$STORE" config commit.gpgsign false
git -C "$STORE" add -A
git -C "$STORE" commit -qm 'Add current contents of password store.'

echo "GNUPGHOME=$GNUPGHOME"
echo "PASSWORD_STORE_DIR=$STORE"
