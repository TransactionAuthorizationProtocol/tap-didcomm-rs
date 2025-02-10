# PRD: JWE Support for DIDComm in Rust (Direct RustCrypto Implementation with WASM & TypeScript Bindings)

This document outlines the requirements and tasks to add JSON Web Encryption (JWE) support for DIDComm messaging in our Rust codebase. The implementation will leverage the `ssi` crate for key management and DID resolution (supporting at least `did:key` and `did:web`) and will implement the JOSE encoding/decoding functionality directly using RustCrypto crates rather than relying on an external JOSE library. In addition, the solution must compile to WebAssembly (WASM) for browser-based applications and include fully tested TypeScript bindings using `jest`.

---

## Overview

- **Objective:**  
  Add full JWE support for DIDComm messaging by implementing the JOSE encoding/decoding directly with RustCrypto primitives. This solution will rely on `ssi` for JWK generation and DID resolution and use RustCrypto crates to perform cryptographic operations (ECDH, HKDF, AES key wrap, content encryption, etc.). The final output must work in a WASM environment and provide TypeScript bindings with comprehensive testing using `jest`.

- **Scope:**  
  - Support DIDComm encryption modes (anoncrypt and authcrypt).  
  - Mandate support for key agreement algorithms:  
    - **ECDH-ES+A256KW** for anoncrypt  
    - **ECDH-1PU+A256KW** for authcrypt  
  - Support content encryption algorithms including:  
    - **A256CBC-HS512** (AES-256-CBC with HMAC-SHA512)  
    - **A256GCM** (AES-256-GCM)  
    - **XC20P** (XChaCha20-Poly1305)  
  - Use `ssi` for:  
    - Generating and managing keys as JWKs  
    - Resolving DIDs (particularly `did:key` and `did:web`) to extract encryption key information  
  - **Custom JOSE Implementation:**  
    - Implement the JOSE encoding and decoding logic directly using RustCrypto crates (e.g., `aes`, `block-modes`, `hmac`, `sha2`, `hkdf`, `aes-kw`, `x25519-dalek`, etc.).  
    - Build the JWE JSON structure (protected header, encrypted key, IV, ciphertext, tag) according to the JOSE/JWE specification.  
  - **WASM Requirement:**  
    - Ensure that the complete solution (including the custom JOSE implementation) compiles to WASM and runs correctly in a browser environment.
  - **TypeScript Bindings:**  
    - Provide TypeScript bindings for the WASM module.  
    - Fully test these bindings using `jest`.

- **Assumptions:**  
  - The existing DIDComm PRD has been implemented.  
  - All cryptographic operations and dependencies must be compatible with compilation to WebAssembly and execution in a browser.  
  - TypeScript bindings will be generated (likely via `wasm-bindgen` or similar tooling) and must include a full testing suite using `jest`.

---

## Important Findings (Context for Implementation)

- **DIDComm Requirements:**  
  - **Key Agreement:**  
    - For anoncrypt, use ECDH-ES+A256KW (ephemeral key generation).  
    - For authcrypt, use ECDH-1PU+A256KW (requires both sender and recipient key material).  
  - **Content Encryption:**  
    - Support for A256CBC-HS512 and A256GCM is mandatory.  
    - The design should allow for future support of XC20P.
  
- **Using `ssi`:**  
  - The `ssi` crate will be used to generate keys as JWKs and resolve DIDs (supporting `did:key` and `did:web` methods).  
  - Keys extracted from DID Documents may be in `publicKeyJwk` or `publicKeyMultibase` format; our implementation must handle both.

- **Custom JOSE Implementation using RustCrypto:**  
  - Instead of integrating an off-the-shelf JOSE library, the encryption and decryption functionality will be implemented directly using RustCrypto crates.  
  - This includes:  
    - Performing ECDH key agreement (using `x25519-dalek` or similar)  
    - Deriving KEKs via HKDF (using the `hkdf` crate)  
    - Wrapping keys with AES-KW (using the `aes-kw` crate)  
    - Encrypting/decrypting content with AES-256-GCM or AES-256-CBC + HMAC-SHA512 (using crates such as `aes-gcm`, `aes`, `block-modes`, `hmac`, and `sha2`)  
    - Constructing the full JWE structure with base64url-encoded fields and the correct JOSE header as per the spec.

- **WASM & TypeScript Considerations:**  
  - All selected RustCrypto crates and our custom JOSE implementation must be verified to work in a WASM context.  
  - The build system (using `wasm-pack` or equivalent) must target WebAssembly without issues.  
  - TypeScript bindings need to be generated and exposed for browser use, and these must be fully tested using `jest`.

---

## Detailed Tasks

- [x] **Research & Library Evaluation**  
  - [x] Evaluate RustCrypto crates to ensure all required cryptographic operations are supported (ECDH, HKDF, AES-KW, AES-GCM, AES-CBC, HMAC, etc.).  
  - [x] Confirm that these crates are compatible with WASM targets.  
  - [x] Document any gaps or necessary workarounds.

- [x] **Design Integration Architecture**  
  - [x] Define the overall architecture for JWE encryption/decryption flows using a custom JOSE implementation.  
  - [x] Identify modules where `ssi` will be used for JWK generation and DID resolution.  
  - [x] Design the abstraction layer that will pass keys from `ssi` to the custom JOSE implementation.  
  - [x] Specify how the JOSE encoding/decoding will be performed:  
    - Build the JSON structure for the JWE (protected header, encrypted key, IV, ciphertext, tag).  
    - Use base64url encoding for header and payload segments.  
    - Include support for both single and multiple recipients if required.  
  - [x] Plan for conditional compilation or alternative implementations for WASM targets.

- [x] **Implement Key Management and DID Resolution**  
  - [x] Use `ssi` to generate keys as JWKs (e.g., using X25519 for encryption).  
  - [x] Implement functions to resolve recipient DID Documents for `did:key` and `did:web` using `ssi` resolvers.  
  - [x] Extract encryption keys (public JWKs) from the DID Documents (handling both `publicKeyJwk` and `publicKeyMultibase` formats).  
  - [x] Add error handling for cases where DID resolution or key extraction fails.  
  - [x] Ensure that the key management code compiles and runs in a WASM environment.

- [x] **Implement Custom JOSE Encoding/Decoding**  
  - [x] Implement functions to generate the JOSE protected header JSON (including `alg`, `enc`, `epk`, and for authcrypt, sender info such as `skid`/`apu`).  
  - [x] Use RustCrypto crates to:  
    - Generate ephemeral keys and perform ECDH (e.g., with `x25519-dalek`).  
    - Derive the KEK using HKDF (using the `hkdf` crate).  
    - Wrap and unwrap the Content Encryption Key (CEK) using AES-KW (using the `aes-kw` crate).  
    - Encrypt and decrypt the message payload using the specified algorithm (A256GCM via `aes-gcm` or A256CBC-HS512 using `aes`, `block-modes`, `hmac`, and `sha2`).  
  - [x] Construct the complete JWE JSON object (or compact serialization) with properly base64url-encoded fields.  
  - [x] Document the JOSE encoding/decoding process with inline comments and external documentation.

- [x] **Implement JWE Encryption Functionality**  
  - [x] Define an API function that accepts a plaintext DIDComm message, sender key, and recipient DID.  
  - [x] Resolve the recipient's DID and extract the encryption key using `ssi`.  
  - [x] Invoke the custom JOSE implementation to:  
    - Generate an ephemeral key (as needed for ECDH-ES or ECDH-1PU).  
    - Perform key agreement and derive the KEK via HKDF.  
    - Wrap the CEK and encrypt the payload.  
    - Build and return the complete JWE JSON structure.  
  - [x] Validate that the encryption functionality works in both native and WASM/browser builds.

- [x] **Implement JWE Decryption Functionality**  
  - [x] Define an API function that accepts a JWE object and the recipient's private key.  
  - [x] For authcrypt mode, resolve the sender's DID to retrieve the sender's public key from the provided header (`skid`/`apu`).  
  - [x] Use the custom JOSE implementation to:  
    - Extract the ephemeral public key from the JWE.  
    - Perform ECDH to derive the KEK (incorporating both sender and recipient keys for authcrypt).  
    - Unwrap the CEK using AES-KW.  
    - Decrypt the ciphertext and return the plaintext.  
  - [x] Implement detailed error handling and logging for debugging purposes.  
  - [x] Ensure decryption works in the WASM/browser environment.

- [x] **WASM-Specific Tasks**  
  - [x] Configure build scripts (using `wasm-pack` or similar) to compile the Rust library to WASM.  
  - [x] Verify that all RustCrypto operations and the custom JOSE implementation are WASM-compatible.  
  - [x] Develop a simple browser-based demo page that uses the WASM module for JWE encryption and decryption.  
  - [x] Document any platform-specific limitations or workarounds for browser usage.

- [x] **Implement TypeScript Bindings**  
  - [x] Generate TypeScript bindings for the WASM module (using `wasm-bindgen` or equivalent tooling).  
  - [x] Expose the encryption and decryption APIs to TypeScript.  
  - [x] Ensure the bindings cover all functionality, including key management, encryption, decryption, and error reporting.

- [x] **Testing & Validation**  
  - [x] Write unit tests in Rust for all new cryptographic functions and JOSE encoding/decoding logic.  
  - [x] Create integration tests that simulate a full DIDComm messaging flow (sender encrypts, recipient decrypts) on the Rust side.  
  - [x] Run tests on both native and WASM builds, ensuring consistent behavior.  
  - [x] Write and run `jest` tests for the TypeScript bindings to verify that the WASM module behaves as expected in the browser environment.  
  - [x] Validate edge cases (e.g., invalid DID, missing key data, unsupported algorithms) and ensure proper error handling.

- [x] **Documentation & Developer Guides**  
  - [x] Update the README and API documentation to describe the new JWE support and custom JOSE implementation.  
  - [x] Provide examples (code snippets) demonstrating how to use the new encryption and decryption functions from Rust and via TypeScript.  
  - [x] Document the WASM build process and provide guidance for integrating the WASM module into browser-based applications.  
  - [x] Include detailed instructions on running the `jest` tests for TypeScript bindings.

- [x] **Code Review & Deployment**  
  - [x] Conduct internal code reviews and verify adherence to cryptographic and security best practices.  
  - [x] Plan for incremental deployment and gather feedback from initial integrations.  
  - [x] Monitor performance and security logs once deployed in staging, including browser usage feedback.

---

## Timeline & Dependencies

- **Timeline:**  
  - Research & Architecture: 1–2 weeks  
  - Implementation (Key management, Custom JOSE, Encryption/Decryption): 3–4 weeks  
  - WASM integration & TypeScript bindings: 1–2 weeks (can overlap with core implementation)  
  - Testing (Rust unit/integration tests + `jest` TypeScript tests) & Documentation: 1–2 weeks  
  - Code review and deployment: 1 week

- **Dependencies:**  
  - `ssi` crate for DID and JWK management  
  - RustCrypto crates (e.g., `aes`, `aes-gcm`, `block-modes`, `hmac`, `sha2`, `hkdf`, `aes-kw`, `x25519-dalek`)  
  - Tools for compiling to WASM (e.g., `wasm-pack`, `wasm-bindgen`)  
  - `jest` for testing TypeScript bindings  
  - Network access for DID resolution (for `did:web`)

---

## Acceptance Criteria

- [ ] The system supports both anoncrypt and authcrypt DIDComm message encryption modes using a custom JOSE implementation.  
- [ ] The custom JOSE encoding/decoding is implemented using RustCrypto crates and conforms to the JWE specification (including correct header, encrypted key, IV, ciphertext, and tag construction).  
- [ ] The implementation leverages `ssi` for JWK management and DID resolution for both `did:key` and `did:web` methods.  
- [ ] The solution compiles to WASM and works correctly in a browser environment.  
- [ ] Fully functional TypeScript bindings are provided, and all bindings are covered by `jest` tests.  
- [ ] Unit and integration tests (both Rust and TypeScript) pass with high coverage, demonstrating correct behavior in native and WASM targets.  
- [ ] Documentation is updated, with clear examples and instructions for both developers and browser integration.

---
