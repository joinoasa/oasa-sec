# Training: roles, device removal and signing-key rotation (R-SEC2)

A hands-on course for people who will run an OASA fleet: take a lost device out, and change a drone's MAVLink signing key when an operator leaves. About 1 hour for steps 1 to 6. One Linux machine, no drone, no radio.

You will be able to: set and read roles; remove a device on one machine and see its link end; revoke a device from an admin and see the news reach a device that is online, refuse a sender that is not its admin, and catch up an admin that was offline; and watch a drone rotate its signing key, with the generation number, the probe and `rotation_stuck`.

> **Prototype.** Not independently reviewed. Do not fly with it. See [SECURITY.md](../SECURITY.md). Design: [oasa-sec-v0-rotation.md](oasa-sec-v0-rotation.md).

## 1. What you need

- A Linux machine with Rust 1.89 or newer and `git`. Nothing else.
- Three terminals are comfortable (one to run commands, one for `tail -f` on a log, one spare). One is enough: every long-running program below runs in the background and writes to a log file.
- Pairing and the link are not repeated here. If a word is new (fingerprint, `oasa-link`, `--peer`, `trust`), do the [R-SEC1 training](training-r-sec1.md) and the [R-COM2 training](training-r-com2.md) first. Here, devices trust each other with `oasa-pair trust`, the short path the R-COM2 guide uses.

Not run here: real autopilots (step 7) and more than one machine.

## 2. Build and set up

```sh
git clone https://github.com/joinoasa/oasa-sec.git && cd oasa-sec
cargo build --locked --bins --examples
```

You should see `Finished` and no errors. Then, in the same terminal:

```sh
REPO=$PWD
export PATH="$REPO/target/debug:$REPO/target/debug/examples:$PATH"
mkdir /tmp/oasa-rsec2 && cd /tmp/oasa-rsec2
key() { oasa-pair show --dir "$1" | sed -E 's/.*"public_key":"([0-9a-f]{64})".*/\1/'; }
fp() { oasa-pair show --dir "$1" | sed -E 's/.*"fingerprint":"([^"]+)".*/\1/'; }
oasa-pair init --dir probe --name probe
oasa-pair show --dir probe
```

```
Created identity 6WCG-B6ND-NJ4R-7YR3
{"name":"probe","public_key":"...64 hex...","fingerprint":"6WCG-B6ND-NJ4R-7YR3"}
```

Your fingerprint differs. `key` and `fp` print a device's public key and fingerprint; later steps use them. (The ports are 91xx to 93xx and 14740. `mkdir` fails if `/tmp/oasa-rsec2` exists: pick another name and use it everywhere.)

Every step has its own device folders and its own ports, so you can redo one without the others. Each step ends with a `pkill` that stops what it started. (`pkill` stops every `oasa-link` on the machine, so do not run this course next to a real link.)

## 3. Roles

Each device keeps a list of the devices it trusts, and gives each a role. The role says what that device may do **here**. Roles are set only on the device, by a person: no message can change one.

| Role | Who | May |
|---|---|---|
| `admin` | 1 to 3 owner devices, kept at base | Remove other devices from this one (step 5) |
| `operator` | A ground station that flies this drone | Fly it, and receive its signing key (step 6) |
| `peer` | Everything else: relays, other drones | Link traffic only. The default |

Make four devices, and let the drone trust the other three with three different roles:

```sh
for d in admin drone gcs spare; do oasa-pair init --dir $d --name $d; done
oasa-pair trust --dir drone --name admin --key "$(key admin)" --role admin
oasa-pair trust --dir drone --name gcs --key "$(key gcs)" --role operator
oasa-pair trust --dir drone --name spare --key "$(key spare)"
oasa-pair peers --dir drone
```

```
Created identity O5MN-BCOU-YJZH-L3BE
...
Trusted admin O5MN-BCOU-YJZH-L3BE as admin
Check that this fingerprint matches the one shown on that device.
Trusted gcs SZDA-3K3B-OUCC-BXZX as operator
Check that this fingerprint matches the one shown on that device.
Trusted spare 5RTC-XB5T-M4AG-GSF4 as peer
Check that this fingerprint matches the one shown on that device.
O5MN-BCOU-YJZH-L3BE  admin  admin
SZDA-3K3B-OUCC-BXZX  operator  gcs
5RTC-XB5T-M4AG-GSF4  peer  spare
```

(On real machines, compare the fingerprint out loud before you trust.) Running `trust` again for the same key and name changes the role:

```sh
oasa-pair trust --dir drone --name spare --key "$(key spare)" --role operator
oasa-pair peers --dir drone
cat drone/trusted-peers.v1
```

```
Changed the role of spare 5RTC-XB5T-M4AG-GSF4 from peer to operator.
O5MN-BCOU-YJZH-L3BE  admin  admin
SZDA-3K3B-OUCC-BXZX  operator  gcs
5RTC-XB5T-M4AG-GSF4  operator  spare
oasa-trusted-peers v1
# <public key> <role> <name>
H4YKW4CY2JWERF5QYOVEHZKR3RD6LRMNJUYRN5LCLLFHHY5RTQEA admin admin
...
```

**This passes when:** `peers` lists the three roles you set. Pairing sets roles by itself: the drone saves the ground station as `operator`, the ground station saves the drone as `peer`. Only `admin` is always by hand.

## 4. Remove a device on one machine

A drone and a ground station that trusts it, with a running link between them:

```sh
for d in rd rg; do oasa-pair init --dir $d --name $d >/dev/null; done
oasa-pair trust --dir rd --name rg --key "$(key rg)" --role operator
oasa-pair trust --dir rg --name rd --key "$(key rd)"
oasa-link --dir rd --peer rg --bind 127.0.0.1:9101 --plain-listen 127.0.0.1:9111 \
  --plain-send 127.0.0.1:9112 --duration 90 > rd.log 2>&1 &
RD=$!
sleep 0.5
oasa-link --dir rg --peer rd --bind 127.0.0.1:9102 --remote 127.0.0.1:9101 --initiate \
  --plain-listen 127.0.0.1:9121 --plain-send 127.0.0.1:9122 --duration 90 > rg.log 2>&1 &
sleep 3
grep session_established rd.log
```

```
Trusted rg 5MW2-P4TK-6IJU-2OVY as operator
Check that this fingerprint matches the one shown on that device.
Trusted rd FT3D-WADA-UXMB-7PFB as peer
Check that this fingerprint matches the one shown on that device.
{"ts":"...","event":"session_established","role":"responder"}
```

The link is up. Now take `rg` off the drone, and ask the drone's `oasa-link` how it ended:

```sh
oasa-pair remove --dir rd rg
wait $RD; echo "exit code $?"
grep -E 'peer_removed|stats' rd.log | cut -c1-120
```

```
Removed rg TP26-OZJ2-7BQK-7H4J (operator).
A running oasa-link notices within a second (or at once on SIGHUP).
exit code 3
{"ts":"...","event":"peer_removed","peer":"TP26-OZJ2-7BQK-7H4J","why":"removed"}
{"ts":"...","event":"stats","sent":0,"received":0,"delivered":0,"control_sent":0,...
```

No restart was needed: `oasa-link` watches the trust files. **Exit code 3 means "my peer was removed"**; a service manager should not restart a link that exits 3. (A plain end after `--duration`, or on `SIGTERM`, is exit code 0.)

Now look at what `remove` left behind, and try to bring the device back:

```sh
oasa-pair peers --dir rd
oasa-pair removed --dir rd
stat -c '%a %n' rd/removed rd/trusted-peers.v1
oasa-pair trust --dir rd --name rg --key "$(key rg)"
oasa-link --dir rd --peer rg --bind 127.0.0.1:9103 --plain-listen 127.0.0.1:9113 \
  --plain-send 127.0.0.1:9114 --duration 1
```

```
No paired devices yet.
TP26-OZJ2-7BQK-7H4J  by hand
600 rd/removed
600 rd/trusted-peers.v1
error: that device was removed here; a removed device must make a new identity and pair again (or undo it with `oasa-pair restore`)
error: no trusted peer named rg; pair first, or `oasa-pair trust`
```

The removal is a **tombstone** in `removed`: an append-only file that wins over `trusted-peers.v1`, even if an old copy of that file comes back. The key cannot be trusted, paired or linked again. "By hand" means a person ran `remove` on this device. The only ways back are a new identity on the removed device (then pair again), or `restore`, which only a person at this device can run, and which does not trust anything by itself:

```sh
oasa-pair restore --dir rd "$(fp rg)"
oasa-pair removed --dir rd
oasa-pair trust --dir rd --name rg --key "$(key rg)" --role operator
oasa-pair peers --dir rd
pkill -TERM oasa-link
```

```
Restored 5MW2-P4TK-6IJU-2OVY. It is not trusted yet: pair it or `oasa-pair trust` it again. Entries already received for it are not applied again; a new one removes it again.
Nothing removed.
Trusted rg TP26-OZJ2-7BQK-7H4J as operator
Check that this fingerprint matches the one shown on that device.
TP26-OZJ2-7BQK-7H4J  operator  rg
```

**This passes when:** the link exits with code 3 and logs `peer_removed`; `removed` lists the device; `trust` and a new `oasa-link` for it are refused.

## 5. Revoke from an admin

`remove` works on one machine. In a fleet you do not want to visit every device. An **admin** keeps a numbered **removal log**; `oasa-pair revoke` adds the device to that log and removes it locally. A device that lists this admin as `admin` gets the news over the encrypted link. Setup: `dev` is a device with two links, one to the admin `adm`, one to `vic` (the device that will be revoked). `dev3` is a second device that does **not** list `adm` as admin.

```sh
for d in adm dev dev3 vic vic2; do oasa-pair init --dir $d --name $d >/dev/null; done
trust_as() { oasa-pair trust --dir "$1" --name "$2" --key "$(key "$3")" --role "$4" >/dev/null; }
trust_as dev adm adm admin;  trust_as dev vic vic peer;  trust_as dev vic2 vic2 peer
trust_as adm dev dev peer;   trust_as adm vic vic peer;  trust_as adm vic2 vic2 peer
trust_as vic dev dev peer
trust_as dev3 adm adm peer;  trust_as adm dev3 dev3 peer
link() { # logname dir encport peer [flags]: plain ports are encport+100 and +200
  local n=$1 d=$2 p=$3 peer=$4; shift 4
  oasa-link --dir $d --peer $peer --bind 127.0.0.1:$p --plain-listen 127.0.0.1:$((p+100)) \
    --plain-send 127.0.0.1:$((p+200)) --duration 90 "$@" > $n.log 2>&1 &
}
link dev-adm dev 9120 adm
link dev-vic dev 9121 vic; DEVVIC=$!
link vic vic 9122 dev --remote 127.0.0.1:9121 --initiate
link adm adm 9123 dev --remote 127.0.0.1:9120 --initiate; ADM=$!
link dev3 dev3 9124 adm
link adm-dev3 adm 9125 dev3 --remote 127.0.0.1:9124 --initiate
sleep 4
```

Six `oasa-link` processes run now. Revoke `vic` from the admin, and watch the news arrive:

```sh
oasa-pair revoke --dir adm vic
wait $DEVVIC; echo "exit code $?"
grep -h -E 'removal_entry|peer_removed|not_admin_here' dev-adm.log dev-vic.log adm-dev3.log
```

```
Removed vic ZB3Q-3FZ5-PPVZ-SOOE (peer).
A running oasa-link notices within a second (or at once on SIGHUP).
Added to this device's removal log as entry 1 of log 46a175be. Devices that list this one as admin get it when their link is up.
exit code 3
{"ts":"...","event":"removal_entry","key":"ZB3Q-3FZ5-PPVZ-SOOE","seq":1,"detail":"removed"}
{"ts":"...","event":"peer_removed","peer":"ZB3Q-3FZ5-PPVZ-SOOE","why":"removed"}
{"ts":"...","event":"not_admin_here"}
```

Three things happened:
1. **The admin's entry travelled over its link to `dev`** (`removal_entry` in `dev-adm.log`). `dev` tombstoned `vic`.
2. **`dev`'s other link, the one to `vic`, ended with exit code 3** (`peer_removed` in `dev-vic.log`). The news travelled on, to a link that has nothing to do with the admin.
3. **`dev3` answered NOT_ADMIN** (`not_admin_here` in `adm-dev3.log`, the admin's side). It does not list `adm` as admin, so it applied nothing. The admin only learns that it was refused.

Check the files:

```sh
oasa-pair removed --dir dev
oasa-pair peers --dir dev
oasa-pair removed --dir dev3
cat adm/removal-log
ls dev/removal-sync
```

```
ZB3Q-3FZ5-PPVZ-SOOE  by admin 5BJA-7YVC-4ISN-AGKT
5BJA-7YVC-4ISN-AGKT  admin  adm
WJAS-LQLH-UCJE-U4CZ  peer  vic2
Nothing removed.
46a175be
1 SBEMCMU6TFKM5EUUR6ZADDQJA6GJQKF3JKNREFWLDIT7VWJ3C5NQ 1793906914
5BJA-7YVC-4ISN-AGKT
```

`removed` names the admin that ordered it. `removal-log` is the admin's list: log id, then `seq key time`. `removal-sync/` remembers, per admin, how far this device has caught up.

**An admin that is offline catches the device up later.** Stop the admin's link, revoke `vic2` while it is down, and see that `dev` does not know yet. Then start the admin's link again:

```sh
kill -TERM $ADM; wait $ADM; echo "admin link exit code $?"
oasa-pair revoke --dir adm vic2
oasa-pair removed --dir dev | wc -l
link adm2 adm 9126 dev --remote 127.0.0.1:9120 --initiate
sleep 4
oasa-pair removed --dir dev | wc -l
grep -h removal_entry dev-adm.log | cut -c1-140
pkill -TERM oasa-link
```

```
admin link exit code 0
Removed vic2 WJAS-LQLH-UCJE-U4CZ (peer).
...
Added to this device's removal log as entry 2 of log 46a175be. ...
1
2
{"ts":"...","event":"removal_entry","key":"ZB3Q-3FZ5-PPVZ-SOOE","seq":1,"detail":"removed"}
{"ts":"...","event":"removal_entry","key":"WJAS-LQLH-UCJE-U4CZ","seq":2,"detail":"removed"}
```

At the start of every session the device and the admin compare how far the log has got, and the admin sends what is missing. Order and repeats do not matter: a removal is only ever added, never undone by a late or doubled message.

**This passes when:** `dev`'s other link exits with code 3; `dev3` removed nothing and the admin logged `not_admin_here`; `dev` shows both revoked keys, the second only after the admin's link came back.

Two limits to know. Removing an **admin** needs entries from two different admins (as that device counts them); with fewer than three admins, remove a stolen admin by hand on each device. And a stolen admin can remove devices until someone removes it: keep admins at base. See [the spec](oasa-sec-v0-rotation.md#3-removing-a-device).

## 6. Signing-key rotation on a drone

The autopilot has one MAVLink signing key, shared with its operators. Someone who ever held it can sign commands. So when an operator leaves, the drone **rotates** the key. Each key has a **generation** number that is never reused. `oasa-pair signer` runs on the drone, owns a dedicated link to the autopilot, waits until it is disarmed, and does the change. The drone's `oasa-link` hands the new key to the remaining operators, inside the encrypted link.

The stand-in autopilot (`examples/fake_autopilot.rs`) behaves like PX4 and ArduPilot here. Files switch it: `ap-armed` makes it armed, `ap-silent` makes it say nothing.

Setup: a drone `sd` with two operators, `o1` and `o2`. Both hold the starting key (as after pairing). The autopilot is loaded with the same key, the signer runs, and `o2` has a live link to the drone:

```sh
for d in sd o1 o2; do oasa-pair init --dir $d --name $d >/dev/null; done
head -c 40 /dev/urandom > sd/mavlink-signing-key.bin
chmod 600 sd/mavlink-signing-key.bin
SDFP=$(fp sd)
for o in o1 o2; do
  mkdir -p $o/signing-keys && chmod 700 $o/signing-keys
  cp sd/mavlink-signing-key.bin $o/signing-keys/$SDFP.bin && chmod 600 $o/signing-keys/$SDFP.bin
  oasa-pair trust --dir sd --name $o --key "$(key $o)" --role operator >/dev/null
  oasa-pair trust --dir $o --name sd --key "$(key sd)" >/dev/null
done
head -c 32 sd/mavlink-signing-key.bin > ap.key
fake_autopilot udpin:127.0.0.1:14740 --armed-file ap-armed --silent-file ap-silent \
  --state-file ap.key > ap.log 2>&1 &
oasa-link --dir sd --peer o2 --bind 127.0.0.1:9132 --plain-listen 127.0.0.1:9232 \
  --plain-send 127.0.0.1:9332 --duration 600 > sd-o2.log 2>&1 &
oasa-link --dir o2 --peer sd --bind 127.0.0.1:9133 --remote 127.0.0.1:9132 --initiate \
  --plain-listen 127.0.0.1:9233 --plain-send 127.0.0.1:9333 --duration 600 > o2.log 2>&1 &
oasa-pair signer --dir sd --autopilot udpout:127.0.0.1:14740 > signer.log 2>&1 &
sleep 4
cat signer.log
```

A pairing with `oasa-pair drone --autopilot …` makes all this for you: see the R-SEC1 guide.

```
{"ts":1793906938,"event":"signer_started"}
```

Both operators can command the autopilot with the starting key (`command` sends one signed test command and waits for a signed answer):

```sh
oasa-pair command --dir o1 --to udpout:127.0.0.1:14740 --wait 10
oasa-pair command --dir o2 --to udpout:127.0.0.1:14740 --wait 10
ls sd | grep signing
```

```
Signed acknowledgment received from 1:1: MAV_CMD_REQUEST_MESSAGE accepted.
Signed acknowledgment received from 1:1: MAV_CMD_REQUEST_MESSAGE accepted.
mavlink-signing-key.bin
```

No `mavlink-signing-gen` yet: no rotation has ever happened.

### Demote an operator, with the autopilot armed

Making an operator anything else is the same risk as removing it: it may hold the key. So demoting asks for a rotation too. Arm the stand-in first. The signer must not touch an armed autopilot:

```sh
touch ap-armed
sleep 2
oasa-pair trust --dir sd --name o1 --key "$(key o1)" --role peer
cat sd/rotation-pending
sleep 5
cat signer.log
```

```
Changed the role of o1 CA3R-AIXO-2GPN-Q72N from operator to peer.
It may hold this drone's signing key, so a new key was requested. `oasa-pair signer` changes it once the autopilot is disarmed.
1793906942 operator-role-changed CA3R-AIXO-2GPN-Q72N 0
{"ts":1793906938,"event":"signer_started"}
{"ts":1793906943,"event":"rotation_waiting_armed"}
```

`rotation-pending` is the request (time, reason, device); it lives until the rotation is done. The signer reports `rotation_waiting_armed` and sends nothing to the autopilot. The drone is not grounded: a removed or demoted device already cannot reach it over the link. Now disarm:

```sh
rm ap-armed
sleep 8
cat signer.log
cat sd/mavlink-signing-gen sd/mavlink-signing-key.gen
cat o2/signing-keys/*.gen
ls sd
```

```
{"ts":1793906938,"event":"signer_started"}
{"ts":1793906943,"event":"rotation_waiting_armed"}
{"ts":1793906953,"event":"rotation_started","generation":1}
{"ts":1793906953,"event":"rotation_done","generation":1}
1
1
1
device-name
identity.key
link-timestamp-PTHZ-2ZLM-GMVT-REBR
mavlink-signing-gen
mavlink-signing-key.bin
mavlink-signing-key.gen
signing-acked
trusted-peers.v1
```

(`signing-acked` remembers which generation each operator has confirmed. No `.next` and no `rotation-pending` are left.) What the signer did, in order (the full list is in [the spec, section 4](oasa-sec-v0-rotation.md#4-signing-key-rotation)):
1. Made generation 1 (`highest ever issued + 1`) and wrote it to `mavlink-signing-gen` **first**, then the new key to `mavlink-signing-key.next`. Nothing is sent before both are on disk.
2. Sent `SETUP_SIGNING` to the autopilot over its dedicated link, signed with the current key.
3. **The probe:** sent a signed command under the **new** key and waited for a signed answer from the autopilot. Only then does the new key count.
4. Replaced `mavlink-signing-key.bin`, deleted `.next`, cleared `rotation-pending`. `mavlink-signing-key.gen` now says which generation the key file is.

Meanwhile the drone's `oasa-link` to `o2` sent the new key to `o2` (`.next`, then a commit message). Check that `o2` follows and `o1` does not:

```sh
grep -h -E 'signing_key' o2.log | cut -c1-120
oasa-pair command --dir o2 --to udpout:127.0.0.1:14740 --wait 10
oasa-pair command --dir o1 --to udpout:127.0.0.1:14740 --wait 4 2>&1 | cut -c1-90
grep "signing key changed" ap.log
```

```
{"ts":"...","event":"signing_key_next","seq":1,"detail":"stored"}
{"ts":"...","event":"signing_key_commit","seq":1,"detail":"switched"}
Signed acknowledgment received from 1:1: MAV_CMD_REQUEST_MESSAGE accepted.
error: no signed acknowledgment after 4s. Likely causes: (1) the autopilot already has a different signing key, ...
signing key changed from 1:191; signed messages only from now on
```

`o2` works with the new key. `o1`, who was demoted, still holds the old key and the autopilot now ignores it. A device that is **offline** during a rotation gets the new key (and the right generation) when its link comes back.

### On demand, and `rotation_stuck`

`oasa-pair rotate-signing` asks for a rotation without removing anyone (for example every season, or after a laptop was seen unattended). Now make the autopilot go silent first, as if its radio or cable had failed after it took the key:

```sh
touch ap-silent
oasa-pair rotate-signing --dir sd
SECONDS=0
while ! grep -q rotation_stuck signer.log && [ $SECONDS -lt 200 ]; do sleep 2; done
echo "after $SECONDS seconds"
tail -2 signer.log
ls sd
```

```
A signing-key rotation is requested. `oasa-pair signer` does it once the autopilot is disarmed.
after 87 seconds
{"ts":1793906954,"event":"rotation_started","generation":2}
{"ts":1793907039,"event":"rotation_stuck"}
device-name
identity.key
link-timestamp-PTHZ-2ZLM-GMVT-REBR
mavlink-signing-gen
mavlink-signing-key.bin
mavlink-signing-key.gen
mavlink-signing-key.next
rotation-pending
signing-acked
trusted-peers.v1
```

It takes about 90 seconds because the signer asks under each key for 75 seconds (ArduPilot refuses new signed streams for up to a minute after a reboot) before it gives up deciding.

**`rotation_stuck` means: the signer sent the change, and can no longer tell which key the autopilot holds.** So it keeps **both** `mavlink-signing-key.bin` and `mavlink-signing-key.next` and decides nothing. It never deletes a key that might be the autopilot's: if it guessed wrong, the drone would be locked out of its own autopilot. It asks again every 5 minutes, at the next start, and whenever a new request arrives. Fix the cause (autopilot off or unplugged, wrong `--autopilot` address or port, wrong `--target`) and ask again:

```sh
rm ap-silent
oasa-pair rotate-signing --dir sd
sleep 20
tail -3 signer.log
ls sd | grep -E 'next|pending'
```

```
A signing-key rotation is requested. `oasa-pair signer` does it once the autopilot is disarmed.
{"ts":1793907666,"event":"rotation_started","generation":2}
{"ts":1793907750,"event":"rotation_stuck"}
{"ts":1793907760,"event":"rotation_rolled_back","generation":2}
rotation-pending
```

When the autopilot answers again, the signer works out which key it has. Here it never saw the change, so it still has the old key: the signer logs `rotation_rolled_back`, deletes `.next` (the old key stays) and keeps the request pending. It retries with a **new** generation; generation 2 is burnt and never reused. (If the autopilot had taken the new key, the signer would have finished with `rotation_done` instead.) Wait until the retry is done, then check:

```sh
for i in $(seq 60); do grep -q '"generation":3}' signer.log && grep -c rotation_done signer.log | grep -q 2 && break; sleep 2; done
tail -3 signer.log
cat sd/mavlink-signing-gen sd/mavlink-signing-key.gen
ls sd | grep -E 'next|pending' || echo "nothing pending"
pkill -TERM oasa-link; pkill -TERM oasa-pair; pkill fake_autopilot
```

```
{"ts":1793907760,"event":"rotation_rolled_back","generation":2}
{"ts":1793907790,"event":"rotation_started","generation":3}
{"ts":1793907790,"event":"rotation_done","generation":3}
3
3
nothing pending
```

**This passes when:** the armed autopilot is left alone; after disarm there is a `rotation_done` for generation 1, `o2` has the new key and `o1`'s old key stops working; a silent autopilot gives `rotation_stuck` with both key files kept; and a later rotation finishes with a higher generation.

## 7. What to check, and what goes wrong

Files (in a device folder; all are mode 600, folders 700):

```sh
stat -c '%a %n' rd/removed rd/trusted-peers.v1 adm/removal-log dev/removed dev/removal-sync/* \
  sd/mavlink-signing-key.bin sd/mavlink-signing-gen sd/mavlink-signing-key.gen \
  o2/signing-keys/*.bin o2/signing-keys/*.gen
stat -c '%a %n' o2/signing-keys
```

```
600 rd/removed
600 rd/trusted-peers.v1
600 adm/removal-log
600 dev/removed
600 dev/removal-sync/5BJA-7YVC-4ISN-AGKT
600 sd/mavlink-signing-key.bin
600 sd/mavlink-signing-gen
600 sd/mavlink-signing-key.gen
600 o2/signing-keys/ZB63-UYOK-LLD4-IDIK.bin
600 o2/signing-keys/ZB63-UYOK-LLD4-IDIK.gen
700 o2/signing-keys
```

Secrets stay out of the logs. No signing key and no private key appears in any log:

```sh
KEY=$(od -An -tx1 -v -N32 sd/mavlink-signing-key.bin | tr -d ' \n')
IDKEY=$(od -An -tx1 -v adm/identity.key | tr -d ' \n')
grep -l -e "$KEY" -e "$IDKEY" *.log || echo "no key in any log"
```

```
no key in any log
```

The log lines to know (one JSON line each, in `oasa-link` and `oasa-pair signer`):

| Line | Where | Means |
|---|---|---|
| `peer_removed` | `oasa-link` | Its peer was removed. The process exits with code 3 |
| `removal_entry` | `oasa-link` | An admin's removal was applied here (or was already known) |
| `not_admin_here` | `oasa-link` | The device you sent a removal to does not list you as admin |
| `removal_refused` | `oasa-link` | A removal went over a limit (4096 per admin, 64 per session). Not applied, not acked |
| `trust_unreadable` | `oasa-link` | A trust file cannot be read. The link keeps its last good state, **but new removals are not applied** until it is fixed |
| `signing_key_next`, `signing_key_commit` | `oasa-link` on an operator | The new key arrived, then took effect |
| `rotation_waiting_armed`, `rotation_started`, `rotation_done` | `signer` | The normal path (`rotation_waiting_heartbeat`: no heartbeat from the autopilot yet; check the address) |
| `rotation_rolled_back` | `signer` | The autopilot kept the old key. A retry follows with a new generation |
| `rotation_stuck` | `signer` | Cannot tell which key the autopilot has. Both keys kept |
| `rotation_refused` | `signer` | A new timestamp would not fit in 48 bits. Nothing was issued |

Troubleshooting:

| You see | Cause and fix |
|---|---|
| `error: that device was removed here; ...` | The key is a tombstone. Make a new identity on the device and pair again, or `oasa-pair restore` on this device (a person at the device). |
| A removed device's link keeps restarting | A supervisor restarts a link that exits 3. Treat exit code 3 as "do not restart". |
| `revoke` printed "entry N", but a device never got it | That device does not list this one as `admin` (`not_admin_here` on the admin side), or the link is down. Check `oasa-pair peers --dir DEVICE`; roles are set on the device by hand. |
| A device ignores a revoke after a long outage | Entries arrive when a link to the admin is up. Start the link; the device catches up at the next session. |
| Removing an admin does nothing yet | It needs two admins' entries on that device. One vote is kept until a second arrives. |
| `trust_unreadable` | `removed` or `trusted-peers.v1` is damaged or over 16 MiB. Fix or restore the file from a good copy, then `kill -HUP` the link. |
| Signer stays at `rotation_waiting_armed` | The autopilot reports armed. Disarm. It is the safe behavior. |
| `error: link error: another oasa-pair signer is already running for this folder` | One `signer` per folder (`.signer.lock`). Stop the other one. |
| Nothing from the signer after a removal | `oasa-pair signer` must be running. Without it, `rotation-pending` just waits. |
| `rotation_stuck` | See step 6. Fix the autopilot link, then `oasa-pair rotate-signing`. Never delete `.next` by hand. |
| `command` says `no signed acknowledgment` | The autopilot has another key, is armed, just rebooted (ArduPilot: up to a minute), or the address is wrong. After a rotation, the demoted device is *supposed* to get this. |
| `Address already in use` | A link from an earlier step runs: `pkill oasa-link`. |

## 8. On real autopilots

Not run here. The same rotation runs against real PX4 and ArduPilot simulators with `scripts/sitl/px4-sitl-test.sh` and `scripts/sitl/ardupilot-sitl-test.sh` (see [sitl.md](sitl.md); not part of CI). In oasa-lab, the `l1-mavlink-sitl` suite covers it. A real drone also needs the MAVLink guard on (it is on by itself when the folder has `mavlink-signing-key.bin`), so the link never carries `SETUP_SIGNING`. Other components that sign MAVLink (a gimbal, a second computer) need the new key too: v0 supports only the autopilot.

## What to do next

Run `scripts/e2e.sh` and `scripts/link-e2e.sh` (`cargo build --locked --bins --examples` first) to see the same checks run automatically. Read [oasa-sec-v0-rotation.md](oasa-sec-v0-rotation.md) for why the signer keeps both keys when unsure.
