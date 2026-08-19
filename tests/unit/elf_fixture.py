"""Minimal STATIC x86_64 ELF fixtures, generated at test time.

The v0.1 sandbox rootfs contains no system binaries (minimal rootfs,
Step 3 - toolchain layers are a later provisioning step). The approved
execve-bridge command surface is therefore WORKSPACE-PROVIDED
executables. These fixtures are tiny static ELF executables (no
interpreter, no libc, no dynamic loader) generated as raw bytes, so the
CLI sub-phase real-sandbox tests can exercise a real execve inside the
sandbox without adding any dependency or checked-in binary.

x86_64 only - consistent with the seccomp derivation (arch x86_64). The
fixtures only ever run inside the Docker uid-1001 container (gated by
_require_fs); the byte generation itself is platform-independent.

Each ELF uses only syscalls in the 45-syscall allowlist (write,
exit_group) or none at all (the hang fixture: jmp $). All fixtures are
static ET_EXEC at 0x400000 with a single R+X PT_LOAD segment.

Import safety: pure byte generation - no exec, no platform-specific
imports. Nothing here runs on import.
"""

from __future__ import annotations

import struct

# ELF64 header is 64 bytes; program header is 56 bytes; code starts at
# file offset 120 = 0x78, so the entry point is 0x400000 + 0x78.
_CODE_OFFSET = 64 + 56
_ENTRY = 0x400000 + _CODE_OFFSET


def _elf(code: bytes) -> bytes:
    """Wrap ``code`` bytes into a minimal static ET_EXEC ELF64
    (single R+X PT_LOAD segment covering the whole file)."""
    ehdr = bytearray(64)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4] = 2                    # ELFCLASS64
    ehdr[5] = 1                    # little-endian
    ehdr[6] = 1                    # EV_CURRENT
    ehdr[7] = 0                    # System V
    struct.pack_into("<H", ehdr, 16, 2)     # ET_EXEC
    struct.pack_into("<H", ehdr, 18, 62)    # EM_X86_64
    struct.pack_into("<I", ehdr, 20, 1)     # e_version
    struct.pack_into("<Q", ehdr, 24, _ENTRY)
    struct.pack_into("<Q", ehdr, 32, 64)    # e_phoff
    struct.pack_into("<Q", ehdr, 40, 0)     # e_shoff (none)
    struct.pack_into("<I", ehdr, 48, 0)     # e_flags
    struct.pack_into("<H", ehdr, 52, 64)    # e_ehsize
    struct.pack_into("<H", ehdr, 54, 56)    # e_phentsize
    struct.pack_into("<H", ehdr, 56, 1)     # e_phnum
    struct.pack_into("<H", ehdr, 58, 0)     # e_shentsize
    struct.pack_into("<H", ehdr, 60, 0)     # e_shnum
    struct.pack_into("<H", ehdr, 62, 0)     # e_shstrndx
    # PT_LOAD: p_type=1, p_flags=5 (R+X), offset 0, vaddr/paddr
    # 0x400000, filesz/memsz = len(code), align 0x1000.
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000,
                       len(code), len(code), 0x1000)
    return bytes(ehdr) + phdr + code


def build_write_exit(text: bytes, exit_code: int = 0) -> bytes:
    """ELF that writes ``text`` to stdout then exits with ``exit_code``.

    Machine code:
        mov eax, 1                  ; write
        mov edi, 1                  ; fd 1
        lea rsi, [rip+19]           ; buffer (data right after the code)
        mov edx, len(text)
        syscall
        mov eax, 231                ; exit_group - the syscall NUMBER is
                                    ; always 231, never the exit status
        mov edi, exit_code          ; exit status
        syscall
    The code prefix is exactly 36 bytes, so the RIP-relative offset to
    the data is fixed: data starts at 36, the lea's next instruction is
    at 17 -> imm = 36 - 17 = 19."""
    code = bytearray()
    code += b"\xb8\x01\x00\x00\x00"                    # mov eax, 1
    code += b"\xbf\x01\x00\x00\x00"                    # mov edi, 1
    code += b"\x48\x8d\x35" + struct.pack("<i", 19)    # lea rsi, [rip+19]
    code += b"\xba" + struct.pack("<I", len(text))     # mov edx, len
    code += b"\x0f\x05"                                # syscall
    code += b"\xb8\xe7\x00\x00\x00"                    # mov eax, 231
    code += b"\xbf" + struct.pack("<I", exit_code)     # mov edi, exit status
    code += b"\x0f\x05"                                # syscall
    code += text
    assert len(code) - len(text) == 36
    return _elf(bytes(code))


def build_hang() -> bytes:
    """ELF that loops forever with NO syscalls (jmp $) - it survives the
    seccomp filter by never calling anything; only the supervisor's
    external deadline can end it (S-036)."""
    return _elf(b"\xeb\xfe")  # jmp -2 (infinite loop)


class _Asm:
    """Tiny label-based assembler for the env-dump fixture (the only
    fixture with control flow). Emits exactly the instructions below."""

    def __init__(self) -> None:
        self.buf = bytearray()
        self.labels: dict[str, int] = {}
        self._fixups: list[tuple[int, str, str]] = []

    def mark(self, name: str) -> None:
        self.labels[name] = len(self.buf)

    def _emit(self, b: bytes) -> None:
        self.buf += b

    def mov_rax_rsp(self) -> None:
        self._emit(b"\x48\x8b\x04\x24")        # mov rax, [rsp]  (argc)

    def lea_envp(self) -> None:
        # lea r12, [rsp+rax*8+16] - the envp pointer lives in r12 so
        # rsi stays free for the write() buffer (a syscall clobbers
        # rcx/r11 only; r12 survives).
        self._emit(b"\x4c\x8d\x64\xc4\x10")

    def mov_rbx_ptr_r12(self) -> None:
        self._emit(b"\x49\x8b\x1c\x24")        # mov rbx, [r12]

    def add_r12_8(self) -> None:
        self._emit(b"\x49\x83\xc4\x08")        # add r12, 8

    def test_rbx_rbx(self) -> None:
        self._emit(b"\x48\x85\xdb")

    def xor_ecx_ecx(self) -> None:
        self._emit(b"\x31\xc9")

    def mov_al_ptr_rbx_rcx(self) -> None:
        self._emit(b"\x8a\x04\x0b")            # mov al, [rbx+rcx]

    def test_al_al(self) -> None:
        self._emit(b"\x84\xc0")

    def inc_rcx(self) -> None:
        self._emit(b"\x48\xff\xc1")

    def mov_eax_imm(self, v: int) -> None:
        self._emit(b"\xb8" + struct.pack("<I", v))

    def mov_edi_imm(self, v: int) -> None:
        self._emit(b"\xbf" + struct.pack("<I", v))

    def mov_rsi_rbx(self) -> None:
        self._emit(b"\x48\x89\xde")

    def mov_rdx_rcx(self) -> None:
        self._emit(b"\x48\x89\xca")

    def syscall(self) -> None:
        self._emit(b"\x0f\x05")

    def mov_edx_imm(self, v: int) -> None:
        self._emit(b"\xba" + struct.pack("<I", v))

    def add_rsi_8(self) -> None:
        self._emit(b"\x48\x83\xc6\x08")

    def xor_edi_edi(self) -> None:
        self._emit(b"\x48\x31\xff")

    def byte(self, b: int) -> None:
        self._emit(bytes([b]))

    def jmp(self, label: str) -> None:
        self._emit(b"\xeb\x00")
        self._fixups.append((len(self.buf) - 1, "rel8", label))

    def jz(self, label: str) -> None:
        self._emit(b"\x74\x00")
        self._fixups.append((len(self.buf) - 1, "rel8", label))

    def lea_rsi_rip(self, label: str) -> None:
        self._emit(b"\x48\x8d\x35\x00\x00\x00\x00")
        self._fixups.append((len(self.buf) - 4, "lea", label))

    def resolve(self) -> bytes:
        for off, kind, label in self._fixups:
            target = self.labels[label]
            if kind == "rel8":
                delta = target - (off + 1)
                if not -128 <= delta <= 127:
                    raise AssertionError(
                        f"rel8 jump out of range to {label}: {delta}")
                self.buf[off] = delta & 0xFF
            elif kind == "lea":
                delta = target - (off + 4)
                self.buf[off:off + 4] = struct.pack("<i", delta)
        return bytes(self.buf)


def build_env_dump() -> bytes:
    """ELF that walks the envp array on its initial stack (kernel
    setup: rsp -> argc, then argv, then envp, NULL-terminated) and
    writes every ``KEY=value`` string plus a newline to stdout. Used to
    prove the exec'd command sees exactly the sanitized six-variable
    environment (S-034) at execve time."""
    a = _Asm()
    a.mov_rax_rsp()          # argc
    a.lea_envp()             # r12 = envp
    a.mark("loop")
    a.mov_rbx_ptr_r12()      # envp[i]
    a.test_rbx_rbx()
    a.jz("exit")
    a.xor_ecx_ecx()          # strlen counter
    a.mark("strlen")
    a.mov_al_ptr_rbx_rcx()
    a.test_al_al()
    a.jz("wlen")
    a.inc_rcx()
    a.jmp("strlen")
    a.mark("wlen")
    a.mov_eax_imm(1)         # write(1, env, len)
    a.mov_edi_imm(1)
    a.mov_rsi_rbx()
    a.mov_rdx_rcx()
    a.syscall()
    a.mov_eax_imm(1)         # write(1, "\n", 1)
    a.mov_edi_imm(1)
    a.lea_rsi_rip("nl")
    a.mov_edx_imm(1)
    a.syscall()
    a.add_r12_8()            # envp++
    a.jmp("loop")
    a.mark("exit")
    a.mov_eax_imm(231)       # exit_group(0)
    a.xor_edi_edi()
    a.syscall()
    a.mark("nl")
    a.byte(0x0A)
    return _elf(a.resolve())
