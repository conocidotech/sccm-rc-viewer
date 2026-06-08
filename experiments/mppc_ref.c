/* Standalone FreeRDP MPPC reference decompressor (RDP5/64K), ported faithfully
 * from FreeRDP libfreerdp/codec/mppc.c + winpr/include/winpr/bitstream.h.
 * Reads our capture format ([u8 uh][u8 cflags][u16 LE size][size bytes]) and
 * dumps the concatenated decompressed output of every record, so we can diff it
 * against our Rust MppcDecompressor and find any divergence. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef uint8_t BYTE;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef int BOOL;

#define PACKET_COMPRESSED 0x20
#define PACKET_AT_FRONT 0x40
#define PACKET_FLUSHED 0x80
#define WINPR_ASSERT(x) ((void)0)
#define WLog_ERR(tag, ...) fprintf(stderr, __VA_ARGS__)
#define ZeroMemory(p, n) memset((p), 0, (n))

/* ---- winpr wBitStream (accumulator/prefetch reader) ---- */
typedef struct {
    const BYTE* buffer;
    BYTE* pointer;
    UINT32 position;
    UINT32 length;
    UINT32 capacity;
    UINT32 mask;
    UINT32 offset;
    UINT32 prefetch;
    UINT32 accumulator;
} wBitStream;

static inline void BitStream_Prefetch(wBitStream* _bs) {
    (_bs->prefetch) = 0;
    const intptr_t diff = _bs->pointer - _bs->buffer;
    if ((diff + 4) < (intptr_t)_bs->capacity) (_bs->prefetch) |= ((UINT32)_bs->pointer[4] << 24);
    if ((diff + 5) < (intptr_t)_bs->capacity) (_bs->prefetch) |= ((UINT32)_bs->pointer[5] << 16);
    if ((diff + 6) < (intptr_t)_bs->capacity) (_bs->prefetch) |= ((UINT32)_bs->pointer[6] << 8);
    if ((diff + 7) < (intptr_t)_bs->capacity) (_bs->prefetch) |= ((UINT32)_bs->pointer[7] << 0);
}
static inline void BitStream_Fetch(wBitStream* _bs) {
    (_bs->accumulator) = 0;
    const intptr_t diff = _bs->pointer - _bs->buffer;
    if ((diff + 0) < (intptr_t)_bs->capacity) (_bs->accumulator) |= ((UINT32)_bs->pointer[0] << 24);
    if ((diff + 1) < (intptr_t)_bs->capacity) (_bs->accumulator) |= ((UINT32)_bs->pointer[1] << 16);
    if ((diff + 2) < (intptr_t)_bs->capacity) (_bs->accumulator) |= ((UINT32)_bs->pointer[2] << 8);
    if ((diff + 3) < (intptr_t)_bs->capacity) (_bs->accumulator) |= ((UINT32)_bs->pointer[3] << 0);
    BitStream_Prefetch(_bs);
}
static inline void BitStream_Shift(wBitStream* _bs, UINT32 _nbits) {
    if (_nbits == 0) {
    } else if ((_nbits > 0) && (_nbits < 32)) {
        _bs->accumulator <<= _nbits;
        _bs->position += _nbits;
        _bs->offset += _nbits;
        if (_bs->offset < 32) {
            _bs->mask = (UINT32)((1UL << _nbits) - 1UL);
            _bs->accumulator |= ((_bs->prefetch >> (32 - _nbits)) & _bs->mask);
            _bs->prefetch <<= _nbits;
        } else {
            _bs->mask = (UINT32)((1UL << _nbits) - 1UL);
            _bs->accumulator |= ((_bs->prefetch >> (32 - _nbits)) & _bs->mask);
            _bs->prefetch <<= _nbits;
            _bs->offset -= 32;
            _bs->pointer += 4;
            BitStream_Prefetch(_bs);
            if (_bs->offset) {
                _bs->mask = (UINT32)((1UL << _bs->offset) - 1UL);
                _bs->accumulator |= ((_bs->prefetch >> (32 - _bs->offset)) & _bs->mask);
                _bs->prefetch <<= _bs->offset;
            }
        }
    }
}
static void BitStream_Attach(wBitStream* bs, const BYTE* buffer, UINT32 capacity) {
    bs->buffer = buffer;
    bs->pointer = (BYTE*)buffer;
    bs->capacity = capacity;
    bs->length = capacity * 8;
    bs->position = 0;
    bs->offset = 0;
    bs->mask = 0;
    bs->prefetch = 0;
    bs->accumulator = 0;
}

/* ---- MPPC context + decompress (RDP5 path only used) ---- */
typedef struct {
    wBitStream* bs;
    BYTE* HistoryPtr;
    UINT32 HistoryOffset;
    UINT32 HistoryBufferSize;
    BYTE HistoryBuffer[65536];
    UINT32 CompressionLevel;
} MPPC_CONTEXT;

int mppc_decompress(MPPC_CONTEXT* mppc, const BYTE* pSrcData, UINT32 SrcSize,
                    const BYTE** ppDstData, UINT32* pDstSize, UINT32 flags) {
    BYTE Literal;
    BYTE* SrcPtr;
    UINT32 CopyOffset;
    UINT32 LengthOfMatch;
    UINT32 accumulator;
    BYTE* HistoryPtr;
    BYTE* HistoryBuffer;
    BYTE* HistoryBufferEnd;
    UINT32 HistoryBufferSize;
    UINT32 CompressionLevel;
    wBitStream* bs = mppc->bs;

    HistoryBuffer = mppc->HistoryBuffer;
    HistoryBufferSize = mppc->HistoryBufferSize;
    HistoryBufferEnd = &HistoryBuffer[HistoryBufferSize - 1];
    CompressionLevel = mppc->CompressionLevel;
    BitStream_Attach(bs, pSrcData, SrcSize);
    BitStream_Fetch(bs);

    if (flags & PACKET_AT_FRONT) { mppc->HistoryOffset = 0; mppc->HistoryPtr = HistoryBuffer; }
    if (flags & PACKET_FLUSHED) { mppc->HistoryOffset = 0; mppc->HistoryPtr = HistoryBuffer; ZeroMemory(HistoryBuffer, mppc->HistoryBufferSize); }
    HistoryPtr = mppc->HistoryPtr;

    if (!(flags & PACKET_COMPRESSED)) { *pDstSize = SrcSize; *ppDstData = pSrcData; return 1; }

    while ((bs->length - bs->position) >= 8) {
        accumulator = bs->accumulator;
        if (HistoryPtr > HistoryBufferEnd) { WLog_ERR(TAG, "history buffer index out of range\n"); return -1004; }
        if ((accumulator & 0x80000000) == 0x00000000) {
            Literal = ((accumulator & 0x7F000000) >> 24); *(HistoryPtr) = Literal; HistoryPtr++; BitStream_Shift(bs, 8); continue;
        } else if ((accumulator & 0xC0000000) == 0x80000000) {
            Literal = ((accumulator & 0x3F800000) >> 23) + 0x80; *(HistoryPtr) = Literal; HistoryPtr++; BitStream_Shift(bs, 9); continue;
        }
        if (CompressionLevel) { /* RDP5 */
            if ((accumulator & 0xF8000000) == 0xF8000000) { CopyOffset = ((accumulator >> 21) & 0x3F); BitStream_Shift(bs, 11); }
            else if ((accumulator & 0xF8000000) == 0xF0000000) { CopyOffset = ((accumulator >> 19) & 0xFF) + 64; BitStream_Shift(bs, 13); }
            else if ((accumulator & 0xF0000000) == 0xE0000000) { CopyOffset = ((accumulator >> 17) & 0x7FF) + 320; BitStream_Shift(bs, 15); }
            else if ((accumulator & 0xE0000000) == 0xC0000000) { CopyOffset = ((accumulator >> 13) & 0xFFFF) + 2368; BitStream_Shift(bs, 19); }
            else { return -1001; }
        } else {
            if ((accumulator & 0xF0000000) == 0xF0000000) { CopyOffset = ((accumulator >> 22) & 0x3F); BitStream_Shift(bs, 10); }
            else if ((accumulator & 0xF0000000) == 0xE0000000) { CopyOffset = ((accumulator >> 20) & 0xFF) + 64; BitStream_Shift(bs, 12); }
            else if ((accumulator & 0xE0000000) == 0xC0000000) { CopyOffset = ((accumulator >> 16) & 0x1FFF) + 320; BitStream_Shift(bs, 16); }
            else { return -1002; }
        }
        accumulator = bs->accumulator;
        if ((accumulator & 0x80000000) == 0x00000000) { LengthOfMatch = 3; BitStream_Shift(bs, 1); }
        else if ((accumulator & 0xC0000000) == 0x80000000) { LengthOfMatch = ((accumulator >> 28) & 0x0003) + 0x0004; BitStream_Shift(bs, 4); }
        else if ((accumulator & 0xE0000000) == 0xC0000000) { LengthOfMatch = ((accumulator >> 26) & 0x0007) + 0x0008; BitStream_Shift(bs, 6); }
        else if ((accumulator & 0xF0000000) == 0xE0000000) { LengthOfMatch = ((accumulator >> 24) & 0x000F) + 0x0010; BitStream_Shift(bs, 8); }
        else if ((accumulator & 0xF8000000) == 0xF0000000) { LengthOfMatch = ((accumulator >> 22) & 0x001F) + 0x0020; BitStream_Shift(bs, 10); }
        else if ((accumulator & 0xFC000000) == 0xF8000000) { LengthOfMatch = ((accumulator >> 20) & 0x003F) + 0x0040; BitStream_Shift(bs, 12); }
        else if ((accumulator & 0xFE000000) == 0xFC000000) { LengthOfMatch = ((accumulator >> 18) & 0x007F) + 0x0080; BitStream_Shift(bs, 14); }
        else if ((accumulator & 0xFF000000) == 0xFE000000) { LengthOfMatch = ((accumulator >> 16) & 0x00FF) + 0x0100; BitStream_Shift(bs, 16); }
        else if ((accumulator & 0xFF800000) == 0xFF000000) { LengthOfMatch = ((accumulator >> 14) & 0x01FF) + 0x0200; BitStream_Shift(bs, 18); }
        else if ((accumulator & 0xFFC00000) == 0xFF800000) { LengthOfMatch = ((accumulator >> 12) & 0x03FF) + 0x0400; BitStream_Shift(bs, 20); }
        else if ((accumulator & 0xFFE00000) == 0xFFC00000) { LengthOfMatch = ((accumulator >> 10) & 0x07FF) + 0x0800; BitStream_Shift(bs, 22); }
        else if ((accumulator & 0xFFF00000) == 0xFFE00000) { LengthOfMatch = ((accumulator >> 8) & 0x0FFF) + 0x1000; BitStream_Shift(bs, 24); }
        else if (((accumulator & 0xFFF80000) == 0xFFF00000) && CompressionLevel) { LengthOfMatch = ((accumulator >> 6) & 0x1FFF) + 0x2000; BitStream_Shift(bs, 26); }
        else if (((accumulator & 0xFFFC0000) == 0xFFF80000) && CompressionLevel) { LengthOfMatch = ((accumulator >> 4) & 0x3FFF) + 0x4000; BitStream_Shift(bs, 28); }
        else if (((accumulator & 0xFFFE0000) == 0xFFFC0000) && CompressionLevel) { LengthOfMatch = ((accumulator >> 2) & 0x7FFF) + 0x8000; BitStream_Shift(bs, 30); }
        else { return -1003; }

        if ((HistoryPtr + LengthOfMatch - 1) > HistoryBufferEnd) { WLog_ERR(TAG, "history buffer overflow\n"); return -1005; }
        SrcPtr = &HistoryBuffer[(HistoryPtr - HistoryBuffer - CopyOffset) & (CompressionLevel ? 0xFFFF : 0x1FFF)];
        do { *HistoryPtr++ = *SrcPtr++; } while (--LengthOfMatch);
    }
    *pDstSize = (UINT32)(HistoryPtr - mppc->HistoryPtr);
    *ppDstData = mppc->HistoryPtr;
    mppc->HistoryPtr = HistoryPtr;
    return 1;
}

int main(int argc, char** argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <capture.bin> <out.bin>\n", argv[0]); return 2; }
    FILE* f = fopen(argv[1], "rb");
    if (!f) { perror("open capture"); return 1; }
    fseek(f, 0, SEEK_END); long flen = ftell(f); fseek(f, 0, SEEK_SET);
    BYTE* cap = malloc(flen); fread(cap, 1, flen, f); fclose(f);

    FILE* out = fopen(argv[2], "wb");
    MPPC_CONTEXT ctx; memset(&ctx, 0, sizeof(ctx));
    wBitStream bs; memset(&bs, 0, sizeof(bs));
    ctx.bs = &bs;
    ctx.HistoryBufferSize = 65536;
    ctx.HistoryPtr = ctx.HistoryBuffer;
    ctx.HistoryOffset = 0;
    ctx.CompressionLevel = 1; /* RDP5 / K64 */

    long i = 0; int recs = 0; long total_out = 0;
    while (i + 4 <= flen) {
        BYTE uh = cap[i]; BYTE cflags = cap[i+1];
        UINT32 size = cap[i+2] | (cap[i+3] << 8);
        if (i + 4 + size > flen) break;
        const BYTE* data = cap + i + 4;
        i += 4 + size;
        const BYTE* dst = NULL; UINT32 dstsize = 0;
        int r = mppc_decompress(&ctx, data, size, &dst, &dstsize, cflags);
        if (r < 0) { fprintf(stderr, "rec %d: mppc_decompress error %d (uh=%02x cflags=%02x size=%u)\n", recs, r, uh, cflags, size); break; }
        if (dst && dstsize) { fwrite(dst, 1, dstsize, out); total_out += dstsize; }
        recs++;
    }
    fclose(out);
    fprintf(stderr, "decompressed %d records -> %ld bytes\n", recs, total_out);
    free(cap);
    return 0;
}
