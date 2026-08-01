# WRITEUP — Talk to the Daemon (`talkcpi-player`)

- **Challenge category:** pwn / IPC (Unix socket + POSIX message queue + shared memory)
- **Difficulty:** medium
- **Flag:** `fahemsec{60bdf4d920d42b5ee2d845d65bc9fb77}`
- **Artifacts:** `bzImage`, `initramfs.cpio.gz`, `Dockerfile`, `docker-compose.yml`, `run.sh`
- **Remote service:** instanced `ncat --ssl <host> 443` (qemu serial console over socat)
- **Runtime:** the whole challenge is a tiny x86-64 Linux VM (`/ipc_server` daemon running as root inside an initramfs, `init` drops to a `ctf` shell)

---

## 1. TL;DR (30-second summary)

A small Linux "virtual machine" boots up and runs a daemon called `/ipc_server`.
At boot the daemon **reads `/flag` into memory while it still has root privileges**,
then `init` drops us to a normal unprivileged shell (`ctf`). Our job: talk to the
daemon through a secret 3-step handshake and make it hand us the flag back.

The daemon deliberately refuses to give the flag to anyone who hasn't completed
all three "locked doors", and each door uses a different Linux inter-process
communication (IPC) mechanism:

1. **Door 1 — a UNIX socket.** We connect to `/tmp/.hackme.sock` and prove who we
   are (our process ID). In return the daemon gives us a random 8-byte **token**.
2. **Door 2 — a POSIX message queue.** We send the token back through the message
   queue `hackme_mq` together with a small checksum. The daemon checks it and sends
   us a second secret called **token2** on a reply queue.
3. **Door 3 — shared memory + a file "trigger".** We write token2 into a shared
   memory block and create a trigger file. The daemon notices, verifies token2,
   and copies the flag into the shared memory. We read it.

So the whole challenge is: *complete a 3-part handshake across three different IPC
mechanisms*. The trick is that the challenge VM ships only a minimal `busybox`
toolkit, so we have to build a tiny program (a few KB of raw machine code) that
speaks all three protocols, get it into the VM by pasting base64 text into the
console, and run it. It prints the flag.

---

## 2. Plain-English explanation (for non-technical readers)

### What is "a daemon that reads the flag"?

Think of the challenge as a **bank vault**. The vault (the file `/flag`) is opened
only by the security guard (the `ipc_server` daemon). When the computer starts,
the guard is the only one with the key, and he memorises the combination (he reads
the flag into memory while still an administrator). Then the computer gives *us* a
normal, low-privilege shell — we're a guest, we have no key.

The guard is programmed with a strict rule: *"I will only tell you the combination
if you prove you completed my three-step handshake."* The three steps use three
completely different kinds of "walkie-talkie channel":

| Step | Kind of channel | Real-world analogy |
|---|---|---|
| 1 | A **socket** (a phone line) | Showing your ID badge at the front desk |
| 2 | A **message queue** (a mailbox) | Sending the badge number you got at the desk, up to the office |
| 3 | **Shared memory + a trigger file** | Signing a receipt, and the guard leaves the answer on a shared whiteboard |

### The three-step dance, in plain words

- **Step 1 — get a visitor badge.** We open a phone line to
  `/tmp/.hackme.sock`. We send a small note: *"I am process number X"* plus a
  fixed magic word `0x00c0ffee` and a scrambled version of our ID so nobody can
  fake it. The guard verifies our real ID behind the scenes (Linux can ask the
  kernel "who is really on the other end of this phone line?"). If we pass, the
  guard hands us a random 8-character **badge** (the *token*).

- **Step 2 — mail the badge back.** We drop a 16-byte envelope into the mailbox
  `hackme_mq`. The envelope must contain: the word "I am a valid visitor"
  (`0x10`), the exact badge we were given, and a checksum (a simple math scramble
  of the badge) so the guard can tell the envelope wasn't tampered with. If it all
  matches, the guard sends a second secret, **token2**, to the reply mailbox
  `hackme_mq_resp`. token2 is basically *"the guard's own process number scrambled
  with the constant 0x13371337"*.

- **Step 3 — sign and collect.** We write token2 into the first 4 bytes of a shared
  memory block (`/dev/shm/hackme_shm`) and create a file `/tmp/.hackme_trigger`.
  The guard checks this trigger file every fraction of a second. When he sees it,
  he unlinks it and compares the value in shared memory to token2. Match → he
  copies the flag into shared memory, 16 bytes in. We read it and win.

### Why is there even a challenge?

Because the VM gives us almost **no tools**. It has only `busybox` — there is no
Python, no compiler, and the built-in `netcat` cannot talk to Unix sockets at all.
Also the "phone line" handshake needs to send and receive exact binary bytes, and
the mailbox steps need to use Linux system calls that busybox's shell can't reach.

So the exploit is a **tiny self-contained program** (about 10 KB of machine code,
written by hand in assembly, no libraries) that does all three steps using only
Linux system calls, plus a short shell script that smuggles it into the VM as
base64 text and runs it. Pasted into the console, it prints the flag in about a
second.

### The two "gotchas" that make it interesting

The author hid two traps inside the handshake to punish people who use standard
helper tools:

1. **The mailbox name is fussy.** Normal programs open message queues by name with
   a leading slash (e.g. `mq_open("/hackme_mq")`). On this challenge kernel that
   silently fails with "permission denied". The daemon itself strips the slash
   before calling the kernel, so you must open it as `hackme_mq` — no slash.
2. **The reply mailbox expects a bigger envelope than you'd think.** The second
   secret is only 4 bytes, but the reply queue's maximum message size is 64 bytes,
   and the kernel *refuses* to receive into a smaller buffer ("message too big").
   You must receive into a 64-byte buffer and read the first 4 bytes of it.

Both are exactly the kind of thing that looks like a bug in your exploit but is
actually a deliberate filter against the easy/naive solutions.

---

## 3. Technical analysis

### 3.1 The VM and init

The challenge is a qemu x86-64 VM booted with:

```
qemu-system-x86_64 -kernel bzImage -initrd initramfs.cpio.gz -nographic \
  -nic none -monitor none -m 128M -append "console=ttyS0 nokaslr quiet"
```

`init` does the setup:

```sh
mount -t proc none /proc
mount -t sysfs none /sys
mount -t tmpfs none /dev/shm
mount -t mqueue none /dev/mqueue
chmod 600 /flag && chown 0.0 /flag
/ipc_server &                    # daemon (as root) reads /flag into memory now
exec setsid /bin/sh -c 'exec su -l ctf 2>/dev/null'
```

So the daemon reads `/flag` **while root**, keeps it in a buffer, then we become
the `ctf` user. `/ipc_server` is an 856 KB statically-linked, stripped ELF.

### 3.2 The daemon state machine

Reversing the daemon (`main` @ `0x401620`) reveals a simple handshake state
machine stored in `.bss`:

```
state  @ 0x4d03d0   (0 → 1 → 2 → 3)
token  @ 0x4d03d4   (8 bytes, from /dev/urandom, per successful auth)
shm    @ 0x4d03c0   (mmap of /dev/shm/hackme_shm, RW shared)
pid    @ 0x4d03e0   (SO_PEERCRED pid of the accepted client)
token2 @ 0x4d03dc   (4 bytes)
```

Main loop: a `select()` on the listening socket with a 100 ms timeout.

- **socket readable** → accept → `recv` the packet → verify magic + SO_PEERCRED
  pid → set `state=1`, generate token, reply 68 bytes → jump straight to mq step.
- **select timeout** → open `hackme_mq`, `mq_receive` one 16-byte message →
  validate `state==1`, token match, checksum → set `state=2`, compute token2,
  `mq_send` it to `hackme_mq_resp` → then, if `state==2`, poll
  `/tmp/.hackme_trigger` and (on token2 match) copy the flag to `shm+0x10`.

### 3.3 Stage 1 — UNIX socket auth (state 0 → 1)

Endpoint `/tmp/.hackme.sock`, `AF_UNIX`/`SOCK_STREAM`, `chmod 0777`, `listen(5)`.

Client sends 12 bytes:

```
LE32 0x00000002          # command type "auth"
LE32 0x00c0ffee          # magic
LE32 getpid() ^ 0xdeadbeef
```

The daemon reads the peer's real pid via `SO_PEERCRED` and checks
`peer_pid ^ 0xdeadbeef == packet[8:12]`. On success it replies 68 bytes:

```
LE32 0x00                # status ok
u8   token[8]            # from /dev/urandom
u8   pad[56]
```

Failure replies (68-byte ASCII blobs): `AUTH FAIL`, `BAD MAGIC C`, `ACCESS DENIED`,
`CRED FAIL`.

### 3.4 Stage 2 — POSIX message queue (state 1 → 2)

Daemon created `hackme_mq` (maxmsg 10, msgsize 16) and `hackme_mq_resp`
(maxmsg 10, msgsize 64) at startup, mode 0666.

Client sends 16 bytes to `hackme_mq`:

```
LE32 0x00000010            # message type "auth2"
u8   token[8]              # must equal daemon's stored token
LE32 token[0:4] ^ 0x0badcafe   # checksum
```

Daemon verifies (from disassembly @ `0x401ae0`):

```asm
cmp dword [state], 1            ; state must be 1
...
mov rax, qword [0x4d03d4]       ; stored token
cmp qword [msg+4], rax          ; token must match
...
xor eax, 0xbadcafe              ; checksum = token_low ^ 0xbadcafe
cmp eax, dword [msg+12]
```

On success: `state=2` and token2 is sent to `hackme_mq_resp` as a 4-byte message:

```
token2 = daemon_pid ^ daemon_uid ^ 0x13371337
```

(`daemon_uid` is 0, so effectively `daemon_pid ^ 0x13371337`.)

### 3.5 Stage 3 — shared memory + trigger (state 2 → 3)

Daemon loops: `open("/tmp/.hackme_trigger", O_RDONLY)` → if present, `unlink` it,
then check `*(u32*)shm == token2`. If equal, copy the flag buffer to `shm+0x10`
(`memcpy`), set `state=3`.

Client therefore:

1. `open("/dev/shm/hackme_shm", O_RDWR)`; `write` 4-byte token2 at offset 0.
2. `open("/tmp/.hackme_trigger", O_CREAT|O_WRONLY)`; `close` (the daemon unlinks it).
3. Poll: `pread(shm_fd, buf, 64, 0x10)` until first byte is non-zero, print it.

Because the daemon opens/unlinks the trigger *before* checking shared memory, and
we write token2 *before* creating the trigger, there is no race: the daemon only
sees the trigger once our shared memory is already correct.

### 3.6 The two deliberate gotchas (this kernel's mqueue)

1. **Leading-slash rejection.** glibc's `mq_open` strips one leading slash before
   the syscall (the daemon's own wrapper does `add rdi, 1`). On this challenge
   kernel, `mq_open("/hackme_mq", ...)` returns `EACCES`, while
   `mq_open("hackme_mq", ...)` succeeds. Symptom while debugging:
   `errno=13` for every access mode, even `O_RDONLY` on a `0666` queue.
2. **EMSGSIZE on the reply.** `mq_receive(fd, buf, 4, ...)` on `hackme_mq_resp`
   fails with `errno=90` (EMSGSIZE) because the queue was created with
   `mq_msgsize=64`. You must receive into ≥64 bytes and take `buf[0:4]`. Symptom:
   the daemon *does* post token2 (visible as `QSIZE:4` in
   `/dev/mqueue/hackme_mq_resp`), but the naive reader keeps failing.

### 3.7 Why an in-VM binary is required

- busybox `nc` has **no `-U`** (no Unix-socket support) — cannot do stage 1.
- Message queues **cannot be driven through `/dev/mqueue` file redirection**: the
  mqueue fs exposes a status file (`QSIZE:0 NOTIFY:0 ...`), writes fail with
  `I/O error`, and reads return the status line, not a message. Only the
  `mq_open`/`mq_timedsend`/`mq_timedreceive` syscalls (240/241/242/243) can move
  messages.
- No compiler/Python in the VM → the client must be a prebuilt static binary.

---

## 4. Exploitation

### 4.1 The client (raw-syscall static ELF)

A ~10 KB x86-64 static ELF, written in assembly (`/tmp/opencode/full.s`), using only
Linux syscalls (`socket/connect/write/read/close`, `mq_open`=240,
`mq_timedsend`=242, `mq_timedreceive`=243, `open/lseek/nanosleep`). Core flow:

```asm
_start:
    ; stage 1 — socket auth
    pid = getpid()
    pkt = u32(2) ++ u32(0xc0ffee) ++ u32(pid ^ 0xdeadbeef)
    s = socket(AF_UNIX, SOCK_STREAM); connect(s, "/tmp/.hackme.sock")
    write(s, pkt, 12); read 68 bytes -> resp     ; token = resp[4:12]

    ; stage 2 — mq auth2
    msg = u32(0x10) ++ token ++ u32(le32(token[0:4]) ^ 0x0badcafe)
    mq = mq_open("hackme_mq", O_WRONLY)          ; NOTE: no leading '/'
    mq_timedsend(mq, msg, 16, 0, NULL); close(mq)
    mqr = mq_open("hackme_mq_resp", O_RDONLY|O_NONBLOCK)
    loop: n = mq_timedreceive(mqr, tok2, 64, NULL, NULL)   ; 64-byte buffer!
          if n >= 0 break; else nanosleep(200ms)

    ; stage 3 — shm + trigger
    shm = open("/dev/shm/hackme_shm", O_RDWR); write(shm, tok2, 4)
    open("/tmp/.hackme_trigger", O_CREAT|O_WRONLY)
    loop: nanosleep(300ms); pread(shm, flag, 64, 0x10)
          if flag[0] != 0: write(1, flag, 64); exit
```

### 4.2 Delivery into the VM (busybox shell script)

The ELF is base64-encoded and embedded in a short busybox shell script. Pasting the
whole script into the VM console decodes it and runs it:

```sh
#!/bin/sh
cat > /tmp/.b64 <<'EOF'
<base64 of the static ELF, 76 chars/line>
EOF
base64 -d /tmp/.b64 > /tmp/exploit
chmod 755 /tmp/exploit
/tmp/exploit
```

### 4.3 Local validation (before touching the remote)

The protocol was first exercised against the daemon run on the host and inside a
rebuilt initramfs. Two independent debugging signals pinpointed the gotchas:

- `raw mq_open("/hackme_mq") → errno=13 (EACCES)` vs
  `raw mq_open("hackme_mq") → ok` and glibc `mq_open` → ok → the slash issue.
- `first recv errno=90` (EMSGSIZE) on a 4-byte buffer while `/dev/mqueue`
  showed `QSIZE:4` (token2 present) → the 64-byte buffer issue.

End-to-end in the VM (running as `ctf`):

```
=== EXPLOIT OUTPUT ===
fahemsec{run_this_on_remote_server}      <- placeholder /flag in the local copy
```

### 4.4 Actual run against the remote

`ncat --ssl t89-8cf56722ba8d.chals.ctf.sd 443` returns a live qemu console
(SeaBIOS → kernel boot → `Welcome to FlEx's Challenge / Can you talk to the daemon?`
→ `~ $`). Pasting the script at the prompt yields:

```
~ $ /tmp/exploit
fahemsec{60bdf4d920d42b5ee2d845d65bc9fb77}
~ $
```

---

## 5. Flag

```
fahemsec{60bdf4d920d42b5ee2d845d65bc9fb77}
```

---

## 6. Lessons

- **Challenges don't need memory corruption.** A carefully *designed* protocol that
  gates a secret behind multiple IPC mechanisms is just as much "pwn" as a buffer
  overflow — here the win is purely protocol correctness, delivered by a
  hand-written raw-syscall client.
- **When a system call "should work" but returns EACCES/EMSGSIZE, trust the kernel
  behaviour over your assumptions.** `mq_open` name semantics and `mq_msgsize`
  were the two hidden filters; the daemon's own call pattern (stripping the slash,
  64-byte reply queue) was the hint to match.
- **The `/dev/mqueue` filesystem is not a message transport.** `cat`/redirection on
  it shows queue status, not messages; you need the real `mq_*` syscalls.
- **A tiny static ELF is the universal "no-tools" payload.** For minimal VMs with
  only busybox, a ~10 KB assembly blob (pure syscalls) that you can base64-paste
  beats fighting the shell for binary I/O.
- **Validate against the real target.** The local initramfs flag is a placeholder;
  only the live instance proves the full chain (and produces the real flag).
