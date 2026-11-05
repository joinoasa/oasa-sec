# Security review: R-SEC1 identity, pairing code and handshake, signing key handover

**Status:** v0.1, 2026-11-05 · **Kind:** internal review, written by an AI agent (Claude) from the code at `704dce9`; not an outside review · **Owner:** citruscybersec

Part of R-SEC1's release (the security review row in oasa-lab's `docs/release.md`: "of identity storage, the pairing code and handshake, and the signing key handover"). The design is in [oasa-sec-v0-pairing.md](oasa-sec-v0-pairing.md); this page records what an independent read of the code found. It does not replace the human review the release record asks for.

## Scope and method

Commit `704dce9` (`main` plus the re-landed #9, #10 and #11 in PR #19). Read in full: `src/identity.rs`, `src/files.rs`, `src/store.rs`, `src/code.rs`, `src/pairing.rs`, `src/signing.rs`, `src/error.rs`, `src/lib.rs`, `src/bin/oasa-pair.rs`; the parts of `src/rotation.rs`, `src/removal.rs` and `src/bin/oasa-link.rs` that pairing and the trust files touch. Docs: the pairing design, `guide-pairing.md`, `sitl.md`, `release-r-sec1.md`, README. Not reviewed: the link protocol (R-COM2) and the rest of R-SEC2 (roles, removal sync, the signer), which get their own reviews.

Run: `cargo test --locked --workspace` (338 passed, 0 failed). Each finding was checked against the code; M1 and L1 were reproduced with the real binaries (throwaway scripts outside the repo). PR #20 was reviewed for L1.

## Findings

No high-severity finding. One medium finding is to be fixed before R-SEC1 is marked done.

| ID | Severity | Finding | Fix | Status |
|---|---|---|---|---|
| M1 | Medium | **Anyone who can reach the pairing port can jam pairing.** The drone serves one connection at a time (`oasa-pair.rs:405-442`): each gets up to 15 s (`:421`), then a 1 s pause (`:439`); the ground station gives up after 30 s (`:526`). Two idle TCP connections kept queued ahead of the ground station are enough: tried, the ground station failed every time with "pairing took too long". No code or key needed, and the guide's real-device example listens on `0.0.0.0` (`guide-pairing.md:183`). The design doc says a slow sender "can't hold the drone"; that holds for one connection only. | Serve attempts in parallel (a small cap, say 8, first success wins and ends the rest), give the first message a short timeout (one frame of at most 162 bytes; 2-3 s), and drop the 1 s pause or apply it per source. Have the ground station retry within the window. Add a test with several idle connections. | Open |
| L1 | Low | **Unlocked readers race atomic replaces.** `open_private_file` (`files.rs:81-99`) takes `lstat`, then `open`, and refuses when the inodes differ (`:104-109`). Writers rename new files over `trusted-peers.v1`, key and generation files, and readers do not lock, so a reader can fail with "changed while opening". Seen in CI (`tests/pair_cli.rs::many_processes_changing_one_folder_lose_nothing`, from the unlocked `store::load` in `trust`, `oasa-pair.rs:214`); reproduced 16 times in 6000 `oasa-pair peers` runs against a renaming writer. Availability only: it fails closed (an error, never an empty or partial list), and `removed` is append-only so the pairing removal check is not affected. `oasa-link` keeps its last checked state and recovers on the next poll (the watcher recorded the pre-rename signature, `oasa-link.rs:685-705`). | Bounded retry on an inode mismatch. Later, open with `O_NOFOLLOW` and check only the open file (see L2), which removes the window. | Fixed (#20, merged 2026-11-05): retries up to 8 times; verdict below |
| L2 | Low | **The folder is trusted more than it is checked.** File ownership is not checked, only the mode (`files.rs:110-117`; a known limit). The folder's mode is checked only on writes (`ensure_private_dir`, `:16-45`, called from `write_temp`, `append_private_line` and the lock), not when loading the identity or trust list. `open` follows a symlink and blocks on a FIFO before the checks run (`:82-89`), and `append_private_line` skips the check when the file did not exist at its `lstat` (`:144-163`), so a symlink placed in between is followed. All need write access to the device folder (or a shared folder by mistake), or a root process pointed at a user's folder. | Open secret files with `O_NOFOLLOW \| O_NONBLOCK` (and `O_CREAT \| O_EXCL` or `O_NOFOLLOW` in append), check `fstat` only; require the file and the folder to be owned by the effective user and not group/other writable, on reads too. | Open |
| I1 | Info | **The removal check fails open on odd errors.** `load_removed` treats any `lstat` error as "nothing removed" (`removal.rs:242`); `read_private_file_opt` (`files.rs:327-333`) correctly does this only for `NotFound`. The pairing `accept` check uses it (`oasa-pair.rs:424`). | Match `NotFound` only. | Open |
| I2 | Info | **Pairing overwrites an existing role.** `store::add` replaces the entry for the key (`store.rs:274-305`), so an admin that pairs again with a drone becomes an operator there, silently, and its removal log is no longer obeyed. Only the same device (holding the code) can cause it. | Keep the stronger of admin and operator on a re-pair, or say what changed. | Open |
| I3 | Info | **Copies of secrets that are not wiped**, beyond `snow`'s own state (a known limit): stdin's buffer holds the pairing code (`oasa-pair.rs:563-564`), the QR text and `qrcode`'s buffers (`code.rs:111-119`), and `read_private_file` buffers if the file grows while read. | Read the code with a raw `read` into a `Zeroizing` buffer; accept the rest as best effort and say so. | Open |
| I4 | Info | **The pairing code goes to stdout** (`oasa-pair.rs:401-402`). Run as a service, it lands in the journal, readable by its group until the code is used or the window closes. | Note it in the guide; optionally print the code only to a terminal. | Open |
| I5 | Info | **The drone shares the key it read at start** (`oasa-pair.rs:380-384`). If the signer commits a rotation during the window, the new ground station gets the old key and catches up only over `oasa-link` (`rotation.rs:406-415`). Without `--autopilot`, a new key is confirmed and saved with no proof (`:385-389`, `:497`); there is a warning. | Read the key per attempt; refuse to pair a first key without `--autopilot` unless forced. | Open |
| I6 | Info | **The finish is not atomic across both sides.** The drone saves the key and confirms before it saves the ground station (`pairing.rs:237-245`, `oasa-pair.rs:445`); the ground station saves the key before the drone entry (`:528-530`). A failure in between leaves a ground station with the key but not trusted by the drone. Fails closed for the link. | Report it clearly; let the drone save the peer before confirming. | Open |

### PR #20 (fix for L1)

Sound. Each attempt repeats the whole check on what it opened: `lstat`, symlink refusal, `open`, `fstat`, the inode comparison. A mismatch only retries; the result is accepted only when the inodes match, and the mode, type and size checks then run on that open file, exactly as a single attempt. After 8 mismatches it fails as before. No new TOCTOU: a symlink swapped in shows as a mismatch, and the next `lstat` refuses it. The new test fails on the old code (reproduced) and passes with the fix; it merges cleanly onto `704dce9` (`files.rs` is the same). One note: a mismatched attempt has already opened the path, so the FIFO case in L2 is unchanged, not worse.

## Checked and found sound

- **Identity:** X25519 keys from the OS random source via `snow`; the public key recomputed with `curve25519-dalek` and checked against RFC 7748. Never overwritten (`hard_link` from a 0600 temp file, so two processes cannot race). Private key wiped on drop, never in `Debug`, errors or output (`show` prints public data only).
- **Small-order keys** are refused wherever a peer key enters: the trust file, `add`, the pairing code, the handshake (the ground station's static), the link.
- **Files:** written to a 0600 temp file, synced, renamed, parent synced; read with a size cap, the mode checked on the open file, symlinks refused; the trust file parsed strictly (format line, roles, names, duplicates), so a damaged file stops the device. Every read-modify-write runs under `.lock`, and `add` checks `removed` under it.
- **Pairing code:** version byte, 32-byte key, 32-byte fresh secret, 4-byte domain-separated checksum; exact length, version and checksum checks; non-ASCII and short input refused without panics; secret wiped on drop and absent from `Debug`. The secret is the security; the checksum only catches typos. A known-answer test pins the format.
- **Code handling in the CLI:** refused on the command line, read from stdin or a file; `--expect-drone` catches a swapped QR; a removed drone is refused before connecting.
- **Handshake:** `Noise_IKpsk1_25519_ChaChaPoly_BLAKE2s` with a fixed prologue. The drone authenticates message 1 (the code's secret as psk1) before it answers, so a stranger gets no reply; the ground station's key is checked against `removed` before the drone answers or shares anything; the ground station reaches only the drone named by the code. A replayed message 1 gets an answer nobody can read and stops at the next message. Frames are size-capped before reading; every attempt has a deadline over the whole exchange; hostile frames are tested.
- **Who may answer:** one code, one success; failed attempts do not end the window (no lockout); the code is dropped after success.
- **Signing key handover:** fresh 32 random bytes (never zero), sent only inside the Noise transport; a second ground station gets the existing key. The drone sends `SETUP_SIGNING` over its own autopilot link, then needs a `COMMAND_ACK` signed with the new key from the target; unsigned replies are dropped (`allow_unsigned = false`). Nothing is saved on either side unless that check passes. Key files are PX4's 40-byte layout, 0600, atomic. `SigningKey` hides itself in `Debug`.
- **The CLI:** no secrets in arguments, environment or errors; error texts name causes, never keys.
- **Dependencies:** `snow` 0.10.0 (Trail of Bits review noted in the release record); no custom crypto.

## Risks that remain by design

- **Anyone who sees the code can pair once**, and the drone has no confirm button. A code holder on a drone with a key receives it.
- **A swapped QR** pairs the ground station with the wrong device unless `--expect-drone` is used or the fingerprint is compared.
- **PX4 takes the first key unsigned on any link**, and ArduPilot's SERIAL0 always accepts `SETUP_SIGNING`. Pair before flight with the radio off; companion on SERIAL1 or higher.
- **A drone's signing key goes to every operator.** A removed operator's key works until the signer rotates it (R-SEC2).
- **The device folder and the operating system are trusted** (see L2), and so is `snow` (it does not wipe its state).
- **Pairing runs over TCP** (Wi-Fi, Ethernet, USB networking), not the radio.

## Next

Fix M1 (#20 already fixes L1), then re-check both here and mark R-SEC1's security row. L2 and the info findings go into issues. The human review in the release record is still required.
