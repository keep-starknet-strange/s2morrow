# S2morrow

STARK-based aggregation of quantum-resistant signatures.  

This project explores zkVM approach for batch verification of multiple PQ signatures. The goal is compare proving time for different signature schemes, as well as benchmark vs other approaches (e.g. LaBRADOR) in terms of proof size (compression ratio) and verification time. 

Implementation details:
- ZKVM: Cairo
- STARK prover: Stwo
- Signature schemes: NIST candidates — Falcon, Dilithium2, Sphincs+

## Roadmap

- [x] Falcon verification
- [ ] Sphincs+ verification
- [ ] Dilithium verification
- [ ] Proving benchmarks

## References

- [BIP360](https://bip360.org/) Pay to Quantum Resistant Hash
- [PQ Signatures and Scaling Bitcoin with STARKs](https://delvingbitcoin.org/t/post-quantum-signatures-and-scaling-bitcoin-with-starks/1584)
- Related [thread](https://groups.google.com/g/bitcoindev/c/wKizvPUfO7w/m/hG9cwpOABQAJ) in bitcoindev mailing list
- Hash based PQ signatures [part 1](https://research.dorahacks.io/2022/10/26/hash-based-post-quantum-signatures-1/) and [part 2](https://research.dorahacks.io/2022/12/16/hash-based-post-quantum-signatures-2/)