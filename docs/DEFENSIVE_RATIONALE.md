# SubZero Defensive Rationale Index

This document explicitly outlines the architectural trade-offs, security mechanics, and structural rationale for the SubZero appliance.

## 1. Physical Entropy Reliance
Silicon-based True Random Number Generators (TRNGs) inside MCU chips are black boxes subject to silent failures, backdoor implants, and physical degradation. SubZero exclusively relies on observable, physical physical entropy (dice, coins) subjected to real-time Markov and Chi-squared audits in the TUI, shifting trust to verifiable physics.

## 2. COTS Hardware Selection
Specialized security operating systems (Tails) and niche hardware wallets function as targeted watering holes. By deploying a radically minimized amnesic OS on ubiquitous Commercial Off-The-Shelf (COTS) hardware (e.g., used ThinkPads), we disrupt supply chain targeting while maximizing physical hardware availability.

## 3. Alpine Substrate Hardening
Broad hardware compatibility requires standard distribution kernels with loadable kernel modules. To guarantee mathematical impossibility of exfiltration without sacrificing webcam/USB compatibility, the OS build script deterministicly prunes all `net` and `bluetooth` kernel modules from the Alpine root filesystem prior to deployment. The appliance boots physically deaf and blind to radio interfaces.

## 4. RAM Remanence (Cold Boot) Mitigation
System DRAM can retain sensitive key material for minutes post-shutdown if physically chilled. SubZero overrides standard ACPI power hooks by loading a statically compiled RAM-wiping kernel (`memtest86+`) via `kexec` during the exit sequence, proactively overwriting all memory banks before motherboard power cut.

## 5. Development Automation
I aggressively leverage AI-autonomous agents and tools to write code, design test suites, and execute development tasks for this architecture. The token-efficient prompts used to verify and build this exact configuration are intended for peer audit to guarantee reproducibility.
