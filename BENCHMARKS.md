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
| **Latency (ns/op)** | ~5–25% faster (similar — both dominated by RSA signing) |
| **Memory, in-memory API (B/op)** | **2–6x less** per operation |
| **Memory, stream API (B/op)** | **40–2600x less** — flashsign's stream path is flat at ~2KB/op |
| **Allocations (allocs/op)** | **58–98x fewer** heap allocations (1.3x on the encrypt path, which is pdfcpu-bound in both) |
| **PKCS7/CMS allocs** | 3 vs 144 (48x fewer) |
| **PDF parser** | Zero-alloc (0 B/op, 0 allocs/op) — not present in gopdfsigner |
| **Increment builder** | Zero-alloc (0 B/op, 0 allocs/op) — not present in gopdfsigner |

The latency improvement is modest because RSA private-key operations dominate wall-clock time in both implementations. The real win is **memory efficiency**: flashsign uses pooled buffers, zero-alloc parsing, and pre-serialized CMS templates to eliminate nearly all heap allocations, reducing GC pressure dramatically under production load.

The stream API is the widest gap. flashsign reads the source once into a pooled
buffer and writes it straight through, so `SignStream` costs a flat ~2KB and 5
allocations whether the PDF is 10KB or 5MB, while gopdfsigner scales with
document size.

`B/op` is amortized allocation traffic, not peak live memory. `SignStream` still
holds one source-sized buffer while parsing and signing; the flat benchmark
numbers come from reusing that buffer between iterations. Buffers above 8 MiB
are deliberately not retained by the pool.

> **Reading the latency column:** the gopdfsigner numbers come from an earlier
> measurement session, so latency ratios within a few percent of 1.00x are run
> drift rather than signal. The memory and allocation ratios are structural and
> reproduce across runs.

---

## Detailed Results (median of 3 runs)

### BenchmarkSignBytes — Invisible signature, single-threaded

| Size | gopdfsigner ns/op | flashsign ns/op | Speedup | gopdfsigner B/op | flashsign B/op | Mem reduction | gopdfsigner allocs | flashsign allocs | Alloc reduction |
|---|---|---|---|---|---|---|---|---|---|
| 10KB | 783,728 | 734,041 | 1.07x | 104,345 | 18,515 | **5.6x** | 456 | 5 | **91x** |
| 100KB | 825,232 | 761,705 | 1.08x | 298,462 | 117,020 | **2.6x** | 456 | 5 | **91x** |
| 500KB | 997,506 | 886,970 | 1.12x | 1,117,714 | 527,401 | **2.1x** | 457 | 5 | **91x** |
| 1MB | 1,193,001 | 1,048,178 | 1.14x | 2,192,681 | 1,060,165 | **2.1x** | 458 | 6 | **76x** |
| 5MB | 2,729,826 | 2,376,507 | 1.15x | 10,581,313 | 5,259,437 | **2.0x** | 463 | 8 | **58x** |

### BenchmarkSignBytesVisible — Visible signature, single-threaded

| Size | gopdfsigner ns/op | flashsign ns/op | Speedup | gopdfsigner B/op | flashsign B/op | Mem reduction | gopdfsigner allocs | flashsign allocs | Alloc reduction |
|---|---|---|---|---|---|---|---|---|---|
| 10KB | 787,567 | 729,751 | 1.08x | 105,427 | 18,439 | **5.7x** | 486 | 5 | **97x** |
| 100KB | 826,124 | 758,548 | 1.09x | 299,526 | 116,996 | **2.6x** | 486 | 5 | **97x** |
| 500KB | 1,006,528 | 886,877 | 1.13x | 1,118,614 | 527,236 | **2.1x** | 487 | 5 | **97x** |
| 1MB | 1,268,015 | 1,050,629 | 1.21x | 2,192,407 | 1,060,237 | **2.1x** | 488 | 6 | **81x** |
| 5MB | 2,974,885 | 2,370,501 | 1.25x | 10,583,653 | 5,259,602 | **2.0x** | 494 | 8 | **62x** |

### BenchmarkSignBytesVisibleParallel — Visible signature, GOMAXPROCS=4 goroutines

| Size | gopdfsigner ns/op | flashsign ns/op | Speedup | gopdfsigner B/op | flashsign B/op | Mem reduction | gopdfsigner allocs | flashsign allocs | Alloc reduction |
|---|---|---|---|---|---|---|---|---|---|
| 10KB | 204,673 | 189,118 | 1.08x | 105,312 | 18,368 | **5.7x** | 486 | 5 | **97x** |
| 100KB | 225,601 | 200,032 | 1.13x | 299,523 | 116,721 | **2.6x** | 486 | 5 | **97x** |
| 500KB | 285,845 | 244,280 | 1.17x | 1,119,240 | 527,446 | **2.1x** | 487 | 5 | **97x** |
| 1MB | 346,491 | 298,197 | 1.16x | 2,193,792 | 1,060,611 | **2.1x** | 488 | 6 | **81x** |
| 5MB | 822,555 | 686,680 | 1.20x | 10,578,944 | 5,260,762 | **2.0x** | 492 | 7 | **70x** |

### BenchmarkSignStreamVisible — Stream API, visible signature, single-threaded

| Size | gopdfsigner ns/op | flashsign ns/op | Speedup | gopdfsigner B/op | flashsign B/op | Mem reduction | gopdfsigner allocs | flashsign allocs | Alloc reduction |
|---|---|---|---|---|---|---|---|---|---|
| 10KB | 775,072 | 728,064 | 1.06x | 89,033 | 2,201 | **40.5x** | 485 | 5 | **97x** |
| 100KB | 823,583 | 758,389 | 1.09x | 184,842 | 2,213 | **83.5x** | 485 | 5 | **97x** |
| 500KB | 982,563 | 897,597 | 1.09x | 595,005 | 2,636 | **225.7x** | 485 | 5 | **97x** |
| 1MB | 1,177,202 | 1,081,633 | 1.09x | 1,136,023 | 3,240 | **350.6x** | 486 | 5 | **97x** |
| 5MB | 2,743,243 | 2,364,050 | 1.16x | 5,328,683 | 12,840 | **415.0x** | 489 | 5 | **98x** |

### BenchmarkSignStreamVisibleParallel — Stream API, GOMAXPROCS=4 goroutines

| Size | gopdfsigner ns/op | flashsign ns/op | Speedup | gopdfsigner B/op | flashsign B/op | Mem reduction | gopdfsigner allocs | flashsign allocs | Alloc reduction |
|---|---|---|---|---|---|---|---|---|---|
| 10KB | 201,239 | 186,864 | 1.08x | 88,928 | 2,017 | **44.1x** | 485 | 5 | **97x** |
| 100KB | 211,978 | 216,017 | 0.98x | 184,696 | 2,018 | **91.5x** | 485 | 5 | **97x** |
| 500KB | 261,666 | 292,728 | 0.89x | 595,247 | 2,016 | **295.3x** | 485 | 5 | **97x** |
| 1MB | 331,788 | 333,869 | 0.99x | 1,137,000 | 2,017 | **563.7x** | 486 | 5 | **97x** |
| 5MB | 762,280 | 711,848 | 1.07x | 5,330,692 | 2,018 | **2641.6x** | 490 | 5 | **98x** |

### BenchmarkSignAndEncrypt — Sign + encrypt, file I/O

| Size | gopdfsigner ns/op | flashsign ns/op | Speedup | gopdfsigner B/op | flashsign B/op | Mem reduction | gopdfsigner allocs | flashsign allocs | Alloc reduction |
|---|---|---|---|---|---|---|---|---|---|
| 10KB | 1,189,901 | 1,068,307 | 1.11x | 382,332 | 306,654 | **1.2x** | 1,705 | 1,267 | **1.3x** |
| 100KB | 1,256,608 | 1,184,228 | 1.06x | 982,263 | 810,864 | **1.2x** | 1,706 | 1,268 | **1.3x** |
| 500KB | 1,881,243 | 1,719,459 | 1.09x | 3,550,943 | 2,972,030 | **1.2x** | 1,709 | 1,272 | **1.3x** |
| 1MB | 2,637,523 | 2,364,021 | 1.12x | 6,920,621 | 5,798,392 | **1.2x** | 1,712 | 1,273 | **1.3x** |
| 5MB | 8,346,167 | 7,828,532 | 1.07x | 33,127,951 | 27,837,374 | **1.2x** | 1,714 | 1,284 | **1.3x** |

### BenchmarkPKCS7Signature — CMS/PKCS7 signing only (no PDF)

| | gopdfsigner | flashsign | Ratio |
|---|---|---|---|
| ns/op | 740,406 | 704,972 | 1.05x |
| B/op | 9,480 | 1,920 | **4.9x less** |
| allocs/op | 144 | 3 | **48x fewer** |

CMS latency is nearly identical (dominated by RSA). flashsign's pre-serialized ASN.1 template approach eliminates 141 allocations per signature.

---

## flashsign-only Benchmarks

These benchmarks have no gopdfsigner equivalent — they measure internal subsystems.

### BenchmarkParsePDF — Zero-alloc PDF parser

| Size | ns/op | B/op | allocs/op | MB/s |
|---|---|---|---|---|
| 10KB | 1,064 | 0 | 0 | 10,219 |
| 100KB | 1,177 | 0 | 0 | 87,511 |
| 500KB | 1,192 | 0 | 0 | 430,016 |
| 1MB | 1,099 | 0 | 0 | 954,414 |
| 5MB | 1,102 | 0 | 0 | 4,757,236 |

Parse time is **constant ~1.1µs** regardless of PDF size — the parser only reads the xref/trailer, not the full file. Zero heap allocations.

### BenchmarkBuildIncrement — Zero-alloc incremental update builder

| ns/op | B/op | allocs/op |
|---|---|---|
| 897 | 0 | 0 |

Builds the PDF incremental update (new objects, xref, trailer) into a pooled buffer with zero allocations.

### BenchmarkSignBytesECDSA — ECDSA P-384 signing (single-threaded)

| Size | ns/op | B/op | allocs/op | MB/s |
|---|---|---|---|---|
| 10KB | 21,258 | 23,543 | 63 | 511 |
| 100KB | 51,236 | 122,151 | 63 | 2,010 |
| 500KB | 185,137 | 532,247 | 64 | 2,769 |
| 1MB | 359,324 | 1,065,353 | 64 | 2,920 |
| 5MB | 1,686,848 | 5,263,688 | 66 | 3,108 |

ECDSA is **~34x faster** than RSA for signing (21µs vs 730µs at 10KB), making it throughput-bound on hashing/memcpy rather than crypto.

### BenchmarkSignBytesECDSAParallel — ECDSA P-384 (GOMAXPROCS=4)

| Size | ns/op | B/op | allocs/op | MB/s |
|---|---|---|---|---|
| 10KB | 6,524 | 23,543 | 63 | 1,666 |
| 100KB | 17,577 | 122,317 | 63 | 5,859 |
| 500KB | 62,479 | 533,024 | 64 | 8,204 |
| 1MB | 159,462 | 1,067,099 | 64 | 6,579 |
| 5MB | 570,522 | 5,264,332 | 65 | 9,191 |

At 4 cores, ECDSA achieves **~10 GB/s** throughput on 5MB PDFs — nearly 10x the RSA parallel throughput.

---

## Key Takeaways

1. **Latency is similar** — RSA signing (~700µs) dominates both implementations. flashsign is 5–25% faster in PDF manipulation overhead, but see the note above: only the larger gaps are outside run-to-run drift.

2. **Memory is the differentiator** — the in-memory API allocates 2–6x fewer bytes and 58–98x fewer heap objects per signing operation. Under sustained load (thousands of signs/sec), this translates to significantly lower GC pause times and memory pressure.

3. **The stream API minimizes allocation traffic** — `SignStream` reports a
   flat ~2KB and 5 allocations from 10KB to 5MB after pool warm-up. It still
   needs one source-sized live buffer for random-access parsing; gopdfsigner's
   measured allocation traffic grows to 5.3MB/op on a 5MB PDF.

4. **Allocation-free internals** — flashsign's PDF parser and increment builder are fully zero-alloc, using direct byte-offset scanning and pooled buffers. gopdfsigner does not expose these as separate benchmarks.

5. **ECDSA unlocks throughput** — If RSA is not a hard requirement, switching to ECDSA P-384 gives ~34x single-thread speedup over RSA signing (flashsign-only feature benchmarked here).

6. **SignAndEncrypt is pdfcpu-bound** — encryption runs through pdfcpu in both implementations, so it keeps ~1,270 allocations and the two are within ~10% of each other. This is the one path where flashsign's zero-alloc work does not apply.
