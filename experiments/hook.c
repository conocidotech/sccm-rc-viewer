/* 32-bit hook DLL: INLINE HOTPATCH on EncryptMessage/DecryptMessage at their real
 * entry points in sspicli.dll, so we capture plaintext SCCM/RDP frames no matter how
 * the caller reaches them (direct IAT, secur32 forwarder, or — the common case —
 * the SSPI dispatch table from InitSecurityInterfaceW). The previous IAT-value match
 * missed all dispatch-table calls and captured nothing.
 *
 * Hotpatch technique (works because sspicli is /hotpatch-compiled: entry is the
 * 2-byte `8B FF` mov edi,edi preceded by 5 bytes of pad):
 *   - write `E9 <rel32 to hookFn>` at  (target - 5)   [the pad]
 *   - overwrite `8B FF` at target with `EB F9` (jmp -5 -> the pad)
 *   - call original via (target + 2), skipping the short jmp.
 *
 * Dumps small buffers (the WLC channel-command / RPC messages) as hex to
 * C:\Users\you\dev\sccm-rc\hook-frames.txt.
 * Build: i686-w64-mingw32-gcc -shared -o hook.dll hook.c -lpsapi  */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

#define SECBUFFER_DATA 1
typedef struct { ULONG cbBuffer; ULONG BufferType; void *pvBuffer; } SecBuffer;
typedef struct { ULONG ulVersion; ULONG cBuffers; SecBuffer *pBuffers; } SecBufferDesc;
typedef LONG (WINAPI *EncFn)(void*, ULONG, SecBufferDesc*, ULONG);
typedef LONG (WINAPI *DecFn)(void*, SecBufferDesc*, ULONG, ULONG*);

static EncFn realEnc = 0, origEnc = 0;   /* origEnc = realEnc + 2 (past the patched mov edi,edi) */
static DecFn realDec = 0, origDec = 0;
static FILE *fh = 0;
static CRITICAL_SECTION cs;
#define MAXLEN 600

static void dumpDesc(SecBufferDesc *d, char dir) {
    if (!d) return;
    for (ULONG i = 0; i < d->cBuffers; i++) {
        SecBuffer *b = &d->pBuffers[i];
        if (b->BufferType == SECBUFFER_DATA && b->cbBuffer > 0 && b->pvBuffer) {
            EnterCriticalSection(&cs);
            if (fh) {
                ULONG cap = b->cbBuffer < MAXLEN ? b->cbBuffer : MAXLEN;  /* truncate hex */
                fprintf(fh, "%c len=%lu ", dir, b->cbBuffer);
                unsigned char *p = (unsigned char*)b->pvBuffer;
                for (ULONG j = 0; j < cap; j++) fprintf(fh, "%02x", p[j]);
                if (cap < b->cbBuffer) fprintf(fh, "..+%lu", b->cbBuffer - cap);
                fprintf(fh, "\n"); fflush(fh);
            }
            LeaveCriticalSection(&cs);
        }
    }
}

/* EncryptMessage seals IN PLACE: the plaintext is in the buffer BEFORE the real call. */
static LONG WINAPI hookEnc(void *ctx, ULONG qop, SecBufferDesc *msg, ULONG seq) {
    dumpDesc(msg, 'C');
    return origEnc(ctx, qop, msg, seq);
}
/* DecryptMessage unseals IN PLACE: the plaintext is in the buffer AFTER the real call. */
static LONG WINAPI hookDec(void *ctx, SecBufferDesc *msg, ULONG seq, ULONG *qop) {
    LONG r = origDec(ctx, msg, seq, qop);
    dumpDesc(msg, 'S');
    return r;
}

/* Install a hotpatch detour at fn -> hook. Returns the address to call for the
 * original (fn+2), or 0 on failure. Logs the prologue bytes for diagnostics. */
static void *hotpatch(void *fn, void *hook, const char *label) {
    unsigned char *t = (unsigned char*)fn;
    if (fh) {
        fprintf(fh, "# %s prologue: %02x %02x %02x %02x %02x  pad[-5..-1]: %02x %02x %02x %02x %02x\n",
                label, t[0], t[1], t[2], t[3], t[4],
                t[-5], t[-4], t[-3], t[-2], t[-1]);
        fflush(fh);
    }
    if (t[0] != 0x8B || t[1] != 0xFF) {  /* not the mov edi,edi hotpatch stub */
        if (fh) { fprintf(fh, "# %s: no hotpatch stub, skipping\n", label); fflush(fh); }
        return 0;
    }
    DWORD old;
    if (!VirtualProtect(t - 5, 7, PAGE_EXECUTE_READWRITE, &old)) return 0;
    /* pad (t-5): E9 rel32 -> hook */
    LONG rel = (LONG)((unsigned char*)hook - (t - 5) - 5);
    t[-5] = 0xE9;
    *(LONG*)(t - 4) = rel;
    /* entry: EB F9 = jmp -5 (back to the pad) */
    t[0] = 0xEB;
    t[1] = 0xF9;
    VirtualProtect(t - 5, 7, old, &old);
    FlushInstructionCache(GetCurrentProcess(), t - 5, 7);
    return (void*)(t + 2);
}

static DWORD WINAPI worker(LPVOID arg) {
    (void)arg;
    InitializeCriticalSection(&cs);
    fh = fopen("C:\\Users\\you\\dev\\sccm-rc\\hook-frames.txt", "w");
    HMODULE sspi = LoadLibraryA("sspicli.dll");
    HMODULE sec  = LoadLibraryA("secur32.dll");
    if (sspi) { realEnc = (EncFn)GetProcAddress(sspi, "EncryptMessage");
                realDec = (DecFn)GetProcAddress(sspi, "DecryptMessage"); }
    if ((!realEnc || !realDec) && sec) {
        if (!realEnc) realEnc = (EncFn)GetProcAddress(sec, "EncryptMessage");
        if (!realDec) realDec = (DecFn)GetProcAddress(sec, "DecryptMessage");
    }
    if (fh) { fprintf(fh, "# enc=%p dec=%p\n", (void*)realEnc, (void*)realDec); fflush(fh); }
    if (realEnc) origEnc = (EncFn)hotpatch((void*)realEnc, (void*)hookEnc, "EncryptMessage");
    if (realDec) origDec = (DecFn)hotpatch((void*)realDec, (void*)hookDec, "DecryptMessage");
    if (fh) { fprintf(fh, "# origEnc=%p origDec=%p (installed)\n", (void*)origEnc, (void*)origDec); fflush(fh); }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    (void)r;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        CreateThread(0, 0, worker, 0, 0, 0);
    }
    return TRUE;
}
