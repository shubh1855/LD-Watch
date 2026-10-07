# Reference verification

Checked 2026-10-07 against publisher/author-hosted pages. Background literature
does not establish LD-Watch implementation coverage or measured performance.

## Verified metadata

- [Resolving the Correct Library: A Loader-Level Defense Solution Against Shared Object Hijacking](https://arxiv.org/abs/2605.26665), arXiv:2605.26665 (2026). The prior README abbreviated the title.
- [User-space library rootkits revisited: Are user-space detection mechanisms futile?](https://arxiv.org/abs/2506.07827), arXiv:2506.07827 (2025).
- [Trace of the Times: Rootkit Detection through Temporal Anomalies in Kernel Activity](https://arxiv.org/abs/2503.02402), arXiv:2503.02402 (2025). The prior title omitted “in Kernel Activity”.
- [Unmasking the Unseen: A Deep Dive into Modern Linux Rootkits and Detection Strategies](https://www.virusbulletin.com/uploads/pdf/conference/vb2025/papers/Unmasking-the-unseen-a-deep-dive-into-modern-Linux-rootkits-and-their-detection.pdf), Ruben Groenewoud and Remco Sprooten, Virus Bulletin Conference, September 2025.

## Bibliography checks still deferred

IEEE pages below returned a JavaScript/robot verification screen. Exact titles,
authors, year and relevance could not be independently confirmed in this check.
Keep these identifiers for manual verification, not as verified citations:

- [IEEE document 10753555](https://ieeexplore.ieee.org/document/10753555): prior README claimed “Malware Detection on Linux Using Runtime Opcode Tracing (2024)”.
- [IEEE document 10538975](https://ieeexplore.ieee.org/document/10538975): prior README claimed “Anomaly Based Malware Threat Detection on Linux Systems (2024)”.

## Implementation references

- [rtld-audit(7)](https://man7.org/linux/man-pages/man7/rtld-audit.7.html): callback and provider/requester semantics.
- [ld.so(8)](https://man7.org/linux/man-pages/man8/ld.so.8.html): loader variables and secure-execution restrictions.
- [unix(7)](https://man7.org/linux/man-pages/man7/unix.7.html): Unix-domain socket behavior and peer credentials.

The repository's [contract](contract.md) defines its own v1 wire; it is not the
glibc audit callback ABI or a format defined by these publications.
