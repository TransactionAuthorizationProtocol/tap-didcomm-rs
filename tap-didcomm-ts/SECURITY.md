# Security Policy

## Supported Versions

We currently support the following versions with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Security Considerations

The TAP DIDComm implementation prioritizes security through several measures:

1. **Cryptographic Operations**
   - All cryptographic operations are performed in WebAssembly
   - Cryptographic material is zeroized after use
   - Standard cryptographic algorithms are used (no custom implementations)

2. **Memory Management**
   - Secure memory handling through WASM
   - Automatic cleanup of sensitive data
   - Memory limits to prevent DoS attacks

3. **Input Validation**
   - Strict validation of all input messages
   - Type checking through TypeScript
   - Size limits on messages and attachments

4. **Error Handling**
   - Security-preserving error messages
   - No leakage of sensitive information
   - Graceful failure modes

5. **Plugin Security**
   - Isolated plugin execution
   - Controlled access to cryptographic operations
   - Validation of plugin operations

## Reporting a Vulnerability

We take security vulnerabilities seriously. Please report them through one of these channels:

1. **Private Disclosure**:
   - Email: security@notabene.id
   - Subject: [TAP-DIDCOMM-SECURITY] Brief description

2. **Bug Bounty Program**:
   - We participate in the NotaBene bug bounty program
   - Visit https://notabene.id/security for details

Please include the following in your report:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Response Timeline

We aim to respond to security reports within these timeframes:

- **Initial Response**: 24 hours
- **Vulnerability Confirmation**: 48 hours
- **Fix Timeline Communication**: 72 hours
- **Fix Implementation**: Depends on severity
  - Critical: 7 days
  - High: 14 days
  - Medium: 30 days
  - Low: Next release

## Security Best Practices

When using this library:

1. **Key Management**
   - Securely store private keys
   - Rotate keys regularly
   - Use hardware security modules when possible

2. **Message Handling**
   - Validate all messages before processing
   - Implement rate limiting
   - Set appropriate message size limits

3. **Plugin Usage**
   - Validate plugin implementations
   - Test plugin security
   - Monitor plugin behavior

4. **Error Handling**
   - Catch and handle all errors
   - Log security events
   - Monitor for unusual patterns

## Acknowledgments

We would like to thank the following for their contributions to our security:

- The DIDComm specification working group
- The Rust cryptography community
- Our security auditors and reviewers

## Updates

This security policy will be updated as new versions are released and security practices evolve. 