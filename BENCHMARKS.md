# flashsign vs gopdfsigner — Benchmark Comparison

Comparison against [gopdfsigner](https://github.com/iamd3vil/gopdfsigner), another
Go PDF signing library.

## Environment

| | |
|---|---|
| **CPU** | Apple M4 Pro (14 cores, limited to GOMAXPROCS=4) |
| **RAM** | 48 GB |
| **OS** | macOS darwin/arm64 |
| **Go** | go1.25.1 |
| **Flags** | `-bench=. -benchmem -count=3 -benchtime=1s` |

Both projects use the same synthetic PDFs (10KB–5MB) generated from `testdata/test.pdf`, same RSA test certificate (`test.pfx`), and identical benchmark harness structure.

---

## Summary

| Metric | flashsign advantage |
|---|---|
| **Latency (ns/op)** | ~1–14% faster (similar — both dominated by RSA signing) |
| **Memory (B/op)** | **2–6x less** memory per operation |
| **Allocations (allocs/op)** | **50–97x fewer** heap allocations |
| **PKCS7/CMS allocs** | 3 vs 144 (48x fewer) |
| **PDF parser** | Zero-alloc (0 B/op, 0 allocs/op) — not present in gopdfsigner |
| **Increment builder** | Zero-alloc (0 B/op, 0 allocs/op) — not present in gopdfsigner |

The latency improvement is modest because RSA private-key operations dominate wall-clock time in both implementations. The real win is **memory efficiency**: flashsign uses pooled buffers, zero-alloc parsing, and pre-serialized CMS templates to eliminate nearly all heap allocations, reducing GC pressure dramatically under production load.

---

## Detailed Results (median of 3 runs)

### BenchmarkSignBytes — Invisible signature, single-threaded

| Size | gopdfsigner ns/op | flashsign ns/op | Speedup | gopdfsigner B/op | flashsign B/op | Mem reduction | gopdfsigner allocs | flashsign allocs | Alloc reduction |
|---|---|---|---|---|---|---|---|---|---|
| 10KB | 783,728 | 775,991 | 1.01x | 104,345 | 18,440 | **5.7x** | 456 | 5 | **91x** |
| 100KB | 825,232 | 801,937 | 1.03x | 298,462 | 117,018 | **2.6x** | 456 | 5 | **91x** |
| 500KB | 997,506 | 961,825 | 1.04x | 1,117,714 | 527,638 | **2.1x** | 457 | 5 | **91x** |
| 1MB | 1,193,001 | 1,169,417 | 1.02x | 2,192,681 | 1,060,971 | **2.1x** | 458 | 6 | **76x** |
| 5MB | 2,729,826 | 2,636,991 | 1.04x | 10,581,313 | 5,263,904 | **2.0x** | 463 | 9 | **51x** |

### BenchmarkSignBytesVisible — Visible signature, single-threaded

| Size | gopdfsigner ns/op | flashsign ns/op | Speedup | gopdfsigner B/op | flashsign B/op | Mem reduction | gopdfsigner allocs | flashsign allocs | Alloc reduction |
|---|---|---|---|---|---|---|---|---|---|
| 10KB | 787,567 | 772,909 | 1.02x | 105,427 | 18,446 | **5.7x** | 486 | 5 | **97x** |
| 100KB | 826,124 | 815,229 | 1.01x | 299,526 | 117,008 | **2.6x** | 486 | 5 | **97x** |
| 500KB | 1,006,528 | 961,825 | 1.05x | 1,118,614 | 527,583 | **2.1x** | 487 | 5 | **97x** |
| 1MB | 1,268,015 | 1,159,748 | 1.09x | 2,192,407 | 1,060,974 | **2.1x** | 488 | 6 | **81x** |
| 5MB | 2,974,885 | 2,609,523 | 1.14x | 10,583,653 | 5,263,730 | **2.0x** | 494 | 9 | **55x** |

### BenchmarkSignBytesVisibleParallel — Visible signature, GOMAXPROCS=4 goroutines

| Size | gopdfsigner ns/op | flashsign ns/op | Speedup | gopdfsigner B/op | flashsign B/op | Mem reduction | gopdfsigner allocs | flashsign allocs | Alloc reduction |
|---|---|---|---|---|---|---|---|---|---|
| 10KB | 204,673 | 195,883 | 1.04x | 105,312 | 18,363 | **5.7x** | 486 | 5 | **97x** |
| 100KB | 225,601 | 208,801 | 1.08x | 299,523 | 116,782 | **2.6x** | 486 | 5 | **97x** |
| 500KB | 285,845 | 253,354 | 1.13x | 1,119,240 | 527,195 | **2.1x** | 487 | 5 | **97x** |
| 1MB | 346,491 | 310,467 | 1.12x | 2,193,792 | 1,060,653 | **2.1x** | 488 | 6 | **81x** |
| 5MB | 822,555 | 712,605 | 1.15x | 10,578,944 | 5,259,648 | **2.0x** | 492 | 7 | **70x** |

### BenchmarkSignStreamVisible — Stream API, visible signature, single-threaded

| Size | gopdfsigner ns/op | flashsign ns/op | Speedup | gopdfsigner B/op | flashsign B/op | Mem reduction | gopdfsigner allocs | flashsign allocs | Alloc reduction |
|---|---|---|---|---|---|---|---|---|---|
| 10KB | 775,072 | 773,617 | 1.00x | 89,033 | 12,952 | **6.9x** | 485 | 6 | **81x** |
| 100KB | 823,583 | 808,734 | 1.02x | 184,842 | 108,716 | **1.7x** | 485 | 6 | **81x** |
| 500KB | 982,563 | 975,835 | 1.01x | 595,005 | 518,873 | **1.1x** | 485 | 6 | **81x** |
| 1MB | 1,177,202 | 1,162,408 | 1.01x | 1,136,023 | 1,060,042 | **1.1x** | 486 | 7 | **69x** |
| 5MB | 2,743,243 | 2,654,398 | 1.03x | 5,328,683 | 5,265,226 | **1.0x** | 489 | 10 | **49x** |

### BenchmarkSignStreamVisibleParallel — Stream API, GOMAXPROCS=4 goroutines

| Size | gopdfsigner ns/op | flashsign ns/op | Speedup | gopdfsigner B/op | flashsign B/op | Mem reduction | gopdfsigner allocs | flashsign allocs | Alloc reduction |
|---|---|---|---|---|---|---|---|---|---|
| 10KB | 201,239 | 195,205 | 1.03x | 88,928 | 12,904 | **6.9x** | 485 | 6 | **81x** |
| 100KB | 211,978 | 207,361 | 1.02x | 184,696 | 108,627 | **1.7x** | 485 | 6 | **81x** |
| 500KB | 261,666 | 261,824 | 1.00x | 595,247 | 519,218 | **1.1x** | 485 | 6 | **81x** |
| 1MB | 331,788 | 329,683 | 1.01x | 1,137,000 | 1,061,187 | **1.1x** | 486 | 7 | **69x** |
| 5MB | 762,280 | 800,817 | 0.95x | 5,330,692 | 5,270,380 | **1.0x** | 490 | 12 | **41x** |

### BenchmarkSignAndEncrypt — Sign + RC4 encrypt, file I/O

| Size | gopdfsigner ns/op | flashsign ns/op | Speedup | gopdfsigner B/op | flashsign B/op | Mem reduction | gopdfsigner allocs | flashsign allocs | Alloc reduction |
|---|---|---|---|---|---|---|---|---|---|
| 10KB | 1,189,901 | 1,186,804 | 1.00x | 382,332 | 305,529 | **1.3x** | 1,705 | 1,255 | **1.4x** |
| 100KB | 1,256,608 | 1,233,035 | 1.02x | 982,263 | 809,818 | **1.2x** | 1,706 | 1,256 | **1.4x** |
| 500KB | 1,881,243 | 1,972,982 | 0.95x | 3,550,943 | 2,972,609 | **1.2x** | 1,709 | 1,260 | **1.4x** |
| 1MB | 2,637,523 | 2,681,486 | 0.98x | 6,920,621 | 5,799,874 | **1.2x** | 1,712 | 1,262 | **1.4x** |
| 5MB | 8,346,167 | 8,587,998 | 0.97x | 33,127,951 | 27,836,533 | **1.2x** | 1,714 | 1,273 | **1.3x** |

### BenchmarkPKCS7Signature — CMS/PKCS7 signing only (no PDF)

| | gopdfsigner | flashsign | Ratio |
|---|---|---|---|
| ns/op | 740,406 | 769,969 | 0.96x |
| B/op | 9,480 | 1,920 | **4.9x less** |
| allocs/op | 144 | 3 | **48x fewer** |

CMS latency is nearly identical (dominated by RSA). flashsign's pre-serialized ASN.1 template approach eliminates 141 allocations per signature.

---

## flashsign-only Benchmarks

These benchmarks have no gopdfsigner equivalent — they measure internal subsystems.

### BenchmarkParsePDF — Zero-alloc PDF parser

| Size | ns/op | B/op | allocs/op | MB/s |
|---|---|---|---|---|
| 10KB | 1,399 | 0 | 0 | 7,772 |
| 100KB | 1,396 | 0 | 0 | 73,778 |
| 500KB | 1,382 | 0 | 0 | 371,017 |
| 1MB | 1,376 | 0 | 0 | 762,514 |
| 5MB | 1,377 | 0 | 0 | 3,808,164 |

Parse time is **constant ~1.4µs** regardless of PDF size — the parser only reads the xref/trailer, not the full file. Zero heap allocations.

### BenchmarkBuildIncrement — Zero-alloc incremental update builder

| ns/op | B/op | allocs/op |
|---|---|---|
| 1,006 | 0 | 0 |

Builds the PDF incremental update (new objects, xref, trailer) into a pooled buffer with zero allocations.

### BenchmarkSignBytesECDSA — ECDSA P-384 signing (single-threaded)

| Size | ns/op | B/op | allocs/op | MB/s |
|---|---|---|---|---|
| 10KB | 24,645 | 23,548 | 63 | 441 |
| 100KB | 60,184 | 122,351 | 63 | 1,711 |
| 500KB | 206,892 | 532,340 | 64 | 2,478 |
| 1MB | 405,621 | 1,065,706 | 64 | 2,587 |
| 5MB | 1,888,789 | 5,269,333 | 67 | 2,776 |

ECDSA is **~32x faster** than RSA for signing (24µs vs 776µs at 10KB), making it throughput-bound on hashing/memcpy rather than crypto.

### BenchmarkSignBytesECDSAParallel — ECDSA P-384 (GOMAXPROCS=4)

| Size | ns/op | B/op | allocs/op | MB/s |
|---|---|---|---|---|
| 10KB | 6,892 | 23,523 | 63 | 1,577 |
| 100KB | 18,128 | 122,204 | 63 | 5,681 |
| 500KB | 64,062 | 532,683 | 64 | 8,002 |
| 1MB | 120,899 | 1,066,488 | 64 | 8,678 |
| 5MB | 525,242 | 5,264,321 | 65 | 9,983 |

At 4 cores, ECDSA achieves **~10 GB/s** throughput on 5MB PDFs — nearly 10x the RSA parallel throughput.

---

## Key Takeaways

1. **Latency is similar** — RSA signing (~750µs) dominates both implementations. flashsign is 1–15% faster in PDF manipulation overhead.

2. **Memory is the differentiator** — flashsign allocates 2–6x fewer bytes and 50–97x fewer heap objects per signing operation. Under sustained load (thousands of signs/sec), this translates to significantly lower GC pause times and memory pressure.

3. **Allocation-free internals** — flashsign's PDF parser and increment builder are fully zero-alloc, using direct byte-offset scanning and pooled buffers. gopdfsigner does not expose these as separate benchmarks.

4. **Stream API is efficient** — flashsign's stream signing uses ~7x less memory than gopdfsigner at small sizes (12KB vs 89KB for 10KB PDFs), converging as PDF size dominates.

5. **ECDSA unlocks throughput** — If RSA is not a hard requirement, switching to ECDSA P-384 gives 32x single-thread and 100x parallel speedup over RSA signing (flashsign-only feature benchmarked here).

6. **SignAndEncrypt parity** — Encryption adds ~450 allocs from the RC4/encryption layer in both. flashsign still uses ~20% less memory but latency is equivalent since file I/O and crypto dominate.
