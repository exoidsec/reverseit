# reverseit

> **Flag:** `flag{REDACTED}`
> **Difficulty:** Hard
> **Estimated Time:** 4–8 hours
> **Tools Required:** jadx-gui, Ghidra (or IDA Pro), Python 3, Android emulator (optional)

---

## Challenge Overview

You are given a single Android APK: `deepdive.apk`.

The UI shows a "License Validator" with a text input and a **VALIDATE** button. Your goal: find the correct license key (the flag).

Four layers of obfuscation protect it:

| Layer | What it is | Tool |
|-------|-----------|------|
| 1 | Obfuscated Java/Kotlin APK (ProGuard) | jadx-gui |
| 2 | JNI call into native `.so` library | Ghidra / IDA Pro |
| 3 | Custom Virtual Machine in C++ | Manual reversing + Python |
| 4 | Anti-debug + cert-keyed validation | Syscall analysis |

---

## Phase 1 — Decompiling the APK

### Step 1.1: Unpack and Decompile

Drag `deepdive.apk` into **jadx-gui**. You'll see a few classes with ProGuard names: `a`, `b`, `c`, and `MainActivity`.

```
com.deepdive.app
├── a          ← Application class
├── b          ← Native bridge (JNI)
├── c          ← Distraction class ← ⚠️ TARPIT
└── MainActivity
```

### Step 1.2: Trace the onClick Logic

In `MainActivity`, the **VALIDATE** button's listener:

```java
int result = b.nativeCheck(input);
```

No logic here — it's entirely delegated to `b.nativeCheck()`.

### Step 1.3: Find the JNI Declarations

In class `b`:

```java
static native void nativeInit(byte[] certHash);
static native int  nativeCheck(String input);
static native String nativeGetHint();
```

Also notice `b.a(Context)` extracts the **SHA-256 of the APK's signing certificate** and passes it to `nativeInit`. This is important — it means the check is **cert-keyed**. Re-signing the APK will break validation.

### Step 1.4: Spot the Tarpit

Class `c` has:
- An RC4-like `init()` function
- A `decrypt()` function
- A field called `FAKE_ENCRYPTED_FLAG`

The **hint button** in the UI calls `nativeGetHint()`, which returns:
> *"Check com.deepdive.app.c.FAKE_ENCRYPTED_FLAG with the RC4 key from init()"*

If you follow this path, you'll "decrypt" it and get:

```
flag{REDACTED}
```

This is a **tarpit**. It's wrong. Don't waste time on it.

**How to spot dead code:** `c.decrypt()` is never called from any live code path. In jadx, right-click → *Find usages* — zero results from the real check flow.

---

## Phase 2 — Reversing the Native Library

### Step 2.1: Extract the .so

Unzip the APK (it's just a ZIP):

```bash
unzip deepdive.apk -d apk_unpacked
ls apk_unpacked/lib/arm64-v8a/
# libdeepdive.so
```

### Step 2.2: Open in Ghidra

1. Open Ghidra → New Project → Import `libdeepdive.so`
2. Let the ARM64 auto-analysis run
3. In the Symbol Tree, look for exported JNI functions:

```
Java_com_deepdive_app_b_nativeInit
Java_com_deepdive_app_b_nativeCheck
Java_com_deepdive_app_b_nativeGetHint
```

### Step 2.3: Analyze `nativeInit`

```c
void Java_com_deepdive_app_b_nativeInit(JNIEnv *env, jclass cls, jbyteArray certHash) {
    long ptrace_result = syscall(117, 0, 0, 0, 0);  // direct syscall!
    if (ptrace_result != -1) {
        memset(g_cert_key, 0xDE, 32);  // corrupt key if being traced
        return;
    }
    // copy cert hash to g_cert_key
    ...
}
```

**Key finding:** The anti-debug uses a **raw ARM64 syscall** (`svc #0` with `x8=117`), not `libc::ptrace()`. If you have a debugger attached, `ptrace(PTRACE_TRACEME)` will return **0** (success) instead of `-1`, because you're already being traced. This triggers the key corruption.

> **Bypass:** Either don't attach a debugger, or patch the conditional branch at the `cmp` instruction.

### Step 2.4: Analyze `nativeCheck`

Key logic in pseudocode:

```c
int nativeCheck(JNIEnv *env, jclass, jstring input) {
    // 1. Length check: must be 37
    if (len != 37) return -1;
    
    // 2. Format check: must start with "flag{" and end with "}"
    if (strncmp(input, "flag{", 5) || input[36] != '}') return -2;
    
    // 3. Cert key modifier
    uint8_t cert_modifier = g_cert_key[0] ^ KNOWN_CERT_HASH[0];
    // If correct cert: cert_modifier == 0x00 (no-op)
    // If wrong cert:   cert_modifier != 0x00 (corrupts check)
    
    // 4. Run the custom VM
    vm_state_t vm;
    vm_init(&vm);
    int pass = vm_run(&vm, VM_PROGRAM, sizeof(VM_PROGRAM), input, 37);
    
    return pass ? 0 : -3;
}
```

### Step 2.5: Find the Data Blobs in .rodata

In Ghidra's **Defined Data** panel or by searching for the byte arrays near the VM functions, locate two key blobs:

**VM_KEY** (8 bytes, offset near `vm_run`):
```
4B 39 1F 72 A3 55 0D C8
```

**VM_TARGET** (37 bytes):
```
FF 04 29 FC 75 BE 62 4C 81 9B 87 FF AC 1E A4 71
49 5B 88 DC 34 E6 A4 AF 21 03 62 5A 6C 9E 81 B1
3F 5B 88 FC 35
```

---

## Phase 3 — Reversing the Custom VM

This is the hardest part. The `vm_run` function contains a dispatch loop — a `switch` statement on opcode bytes.

### Step 3.1: Map the Instruction Set

By analyzing the switch cases in Ghidra:

| Opcode | Mnemonic | Operands | Semantics |
|--------|----------|----------|-----------|
| `0x00` | `NOP` | — | No-op |
| `0x01` | `LOAD` | reg, imm8 | `reg = imm8` |
| `0x02` | `MOV` | dst, src | `dst = src` |
| `0x03` | `XOR` | dst, src | `dst ^= src` |
| `0x04` | `ADD` | reg, imm8 | `reg = (reg + imm8) & 0xFF` |
| `0x05` | `ROR` | reg, imm8 | `reg = ROR(reg, imm8)` |
| `0x06` | `SUB` | reg, imm8 | `reg = (reg - imm8) & 0xFF` |
| `0x07` | `CMP` | reg, mem | `ZF = (reg == mem[addr])` |
| `0x08` | `JNZ` | rel8 | `if !ZF: PC += (int8)rel8` |
| `0x09` | `RET` | — | Halt; result = `mem[63]` |
| `0x0A` | `LDMEM` | reg, mem | `reg = mem[addr]` |
| `0x0B` | `STMEM` | mem, reg | `mem[addr] = reg` |

**VM Registers:** `r0`–`r7` (8-bit each)

**VM Memory:** 64 bytes (`mem[0]`–`mem[63]`)

**VM Memory Map:**
- `mem[0]` — current input byte (loaded externally per iteration)
- `mem[1]` — current key byte (loaded externally per iteration)
- `mem[2]` — scratch space
- `mem[3]` — target byte (loaded externally per iteration)
- `mem[63]` — result (`1`=pass, `0`=fail); also serves as zero-constant for `CMP`

### Step 3.2: Disassemble the VM_PROGRAM

Run the provided disassembler:

```bash
python3 vm_disasm.py
```

Output:
```
  0000  01 00 00   LOAD r0, 0x00   ; i = 0
  0003  01 07 26   LOAD r7, 0x26   ; loop_limit = 37 (0x25... wait)
  0006  0A 01 00   LDMEM r1, mem[0]; r1 = input[i]
  0009  0A 02 01   LDMEM r2, mem[1]; r2 = key[i%8]
  000C  03 01 02   XOR r1, r2      ; r1 ^= key    ← OP 1
  000F  05 01 03   ROR r1, 0x03    ; r1 = ROR(r1,3) ← OP 2
  0012  04 01 5A   ADD r1, 0x5A    ; r1 += 0x5A   ← OP 3
  0015  0B 02 01   STMEM mem[2],r1
  0018  0A 03 03   LDMEM r3, mem[3]; r3 = target[i]
  001B  03 01 03   XOR r1, r3      ; r1 ^= r3 (0 if match)
  001E  01 04 00   LOAD r4, 0x00
  0021  03 04 01   XOR r4, r1
  0024  07 04 3F   CMP r4, mem[63] ; ZF = (r4 == 0)
  0027  08 10      JNZ +16         ; mismatch → RET_FAIL
  0029  04 00 01   ADD r0, 1       ; i++
  002C  02 05 00   MOV r5, r0
  002F  03 05 07   XOR r5, r7      ; r5 = i ^ 37 (0 when done)
  ...
  003D  01 00 01   LOAD r0, 1
  0040  0B 3F 00   STMEM mem[63],r0
  0043  09         RET             ; ← RET_PASS
  0044  01 00 00   LOAD r0, 0
  0047  0B 3F 00   STMEM mem[63],r0
  004A  09         RET             ; ← RET_FAIL
```

### Step 3.3: Extract the Transform

The VM applies this transform to **each byte** of your input:

```
transformed = ADD( ROR( input[i] XOR key[i%8], 3 ), 0x5A )  mod 256
```

Then checks: `transformed == VM_TARGET[i]`

### Step 3.4: Invert the Transform

To recover the original input byte:

```
Forward:  t = ((ROR(b ^ key, 3)) + 0x5A) & 0xFF
Inverse:  b = ROL((t - 0x5A) & 0xFF, 3) ^ key
```

Where **ROL** is the inverse of ROR (rotate **left** instead of right).

---

## Phase 4 — Solving

Run the solver:

```bash
python3 solver.py
```

The solver:
1. Reads `VM_KEY` and `VM_TARGET` (extracted from `.rodata`)
2. Applies the inverse transform to each of the 37 target bytes
3. Verifies the result re-encrypts to the original targets
4. Prints the flag

---

## The Flag

```
flag{REDACTED}
```

---

## Pitfalls & Lessons Learned

### 🪤 Pitfall 1: The Tarpit (class `c`)

Many analysts will spend an hour decoding `c.FAKE_ENCRYPTED_FLAG` because:
- The hint button points directly to it
- The RC4-like code looks genuinely cryptographic
- The result *looks* like a real flag format

**Lesson:** Always trace data flow. In jadx, check what actually gets called from the validation path. `c.decrypt()` has zero callers on the hot path.

---

### 🪤 Pitfall 2: The Anti-Debug Syscall

If you attach Frida or gdb before `nativeInit` runs, `g_cert_key` gets filled with `0xDE` bytes instead of the real cert hash. This means:
- `cert_modifier = 0xDE ^ 0xA3 = 0x7D` (nonzero)
- The first input byte gets XOR'd with `0x7D` before VM processing
- All comparisons fail silently
- You waste hours wondering why nothing validates

**Lesson:** Look for anti-debug *before* setting breakpoints. The inline assembly `svc #0` hint in Ghidra tells you it's a raw syscall, not a libc call.

**Bypass:** Patch the branch at `nativeInit+0x14` from `b.ne` (branch-not-equal) to `b.eq` in Ghidra, re-export the patched `.so`, and repack the APK. OR just don't attach a debugger and work statically.

---

### 🪤 Pitfall 3: The Certificate Key

If you repack and resign the APK (e.g., to inject Frida gadget), `g_cert_key[0]` will differ from `KNOWN_CERT_HASH[0]`, so `cert_modifier != 0`. This corrupts the check.

**Lesson:** Either:
- Work statically (no repacking needed — all data is in the `.so`)
- Find and patch the `cert_modifier` xor instruction to always produce `0x00`

---

### 🪤 Pitfall 4: The VM Loop Feeding

The `vm_run` function feeds `mem[0]`, `mem[1]`, and `mem[3]` per iteration from outside the VM program itself. If you only look at the bytecode and don't understand the hosting loop, you'll miss that the "external loader" controls what data the VM sees.

**Lesson:** Read the C `vm_run` function carefully, not just the VM program bytes. The hosting loop is part of the puzzle.

---

## Summary of Solution Path

```
APK (jadx-gui)
  └─ Find b.nativeCheck() → delegates to JNI
      └─ libdeepdive.so (Ghidra)
          ├─ Anti-debug: bypass raw ptrace syscall
          ├─ Cert-key: understand cert_modifier (0x00 = correct cert)
          ├─ Locate VM_PROGRAM, VM_KEY, VM_TARGET in .rodata
          └─ Custom VM dispatch loop
              ├─ Map opcodes: XOR, ROR, ADD, CMP, JNZ, RET
              ├─ Disassemble VM_PROGRAM
              ├─ Identify transform: XOR(key) → ROR(3) → ADD(0x5A)
              └─ Invert: SUB(0x5A) → ROL(3) → XOR(key)
                  └─ Apply to VM_TARGET → flag
```

---

## Files Provided

| File | Description |
|------|-------------|
| `apk_source/` | Full Java + JNI source of the challenge |
| `apk_source/src/main/java/com/deepdive/app/` | Java classes (a, b, c, MainActivity) |
| `apk_source/src/main/jni/deepdive.cpp` | Native C++ library source |
| `solver/solver.py` | Complete automated solver |
| `solver/vm_disasm.py` | Custom VM disassembler |
| `walkthrough.md` | This document |

Hope you all like my writeup :)
