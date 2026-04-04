# Rule: The 8 GB Law — Memory Asceticism

All file reads in hot paths MUST use `memmap2::Mmap`. Never use `std::fs::read`
or `read_to_string` in execution paths.

Use `rkyv` zero-copy for IPC and registry persistence. No gratuitous `Vec<u8>`
heap copies.

No unbounded heap allocations. Every collection must have a known upper bound
or a circuit breaker.

`String` clones in hot loops are forbidden. Pass `&str`, not owned values.

## Enforcement checklist

- [ ] New file-reading code uses `Mmap`, not `fs::read`
- [ ] New serialization uses `rkyv`, not ad-hoc `Vec<u8>` copies
- [ ] Collections that grow from external input have a size cap or early exit
- [ ] Hot-loop string operations use `&str` borrows
