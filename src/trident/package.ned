//
// TRIDENT-VNDN - Trust-driven Resilient In-network DEfeNse Tier
//
// Paper 3 of the VeReMiVNDN line: a detector-agnostic, closed-loop, trust-driven
// MITIGATION layer (distinct from the detection-only Papers 1 and 2). It turns a
// per-vehicle malicious-belief stream Bel(v) into a continuous trust state via a
// trust ODE, drives three reversible remediation prongs (trust-aware forwarding,
// poisoning-resilient cache admission, graceful reversible quarantine), and
// measures network resilience as the Area Under the Resilience Curve (AURC) of
// the normalised Interest-satisfaction ratio.
//
package veremivndn.trident;
