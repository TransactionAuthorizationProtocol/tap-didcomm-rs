/**
 * Core types for the DIDComm TypeScript implementation.
 * @module types
 */

/**
 * Supported packing types for DIDComm messages.
 * These determine the level of security and privacy applied to messages.
 */
export enum PackingType {
  /** Messages are only signed, providing authenticity but no encryption */
  SIGNED = 'signed',
  /** Messages are encrypted anonymously, hiding the sender's identity */
  ANONCRYPT = 'anoncrypt',
  /** Messages are encrypted with sender authentication, providing both confidentiality and authenticity */
  AUTHCRYPT = 'authcrypt',
}

/**
 * Represents a DID Document as defined in the DID Core specification.
 * @see {@link https://www.w3.org/TR/did-core/}
 */
export interface DIDDocument {
  /** The DID that identifies this DID Document */
  id: string;
  /** Array of verification methods that can be used to authenticate or authorize interactions */
  verificationMethod?: VerificationMethod[];
  /** Array of verification method references that can be used for authentication */
  authentication?: string[];
  /** Array of verification method references that can be used for key agreement */
  keyAgreement?: string[];
  /** Array of verification method references that can be used for making assertions */
  assertionMethod?: string[];
  /** Array of service endpoints associated with this DID */
  service?: ServiceEndpoint[];
}

/**
 * Represents a verification method in a DID Document.
 * This can be a public key or other verification material.
 */
export interface VerificationMethod {
  /** Unique identifier for this verification method */
  id: string;
  /** The type of verification method (e.g., 'Ed25519VerificationKey2020') */
  type: string;
  /** The DID of the controller of this verification method */
  controller: string;
  /** Optional JWK representation of the public key */
  publicKeyJwk?: JsonWebKey;
  /** Optional multibase-encoded public key */
  publicKeyMultibase?: string;
}

/**
 * Represents a service endpoint in a DID Document.
 * Services are used for discovering ways to interact with the DID subject.
 */
export interface ServiceEndpoint {
  /** Unique identifier for this service */
  id: string;
  /** The type of service (e.g., 'DIDCommMessaging') */
  type: string;
  /** The URL or other address for accessing the service */
  serviceEndpoint: string;
  /** Optional array of routing keys for the service */
  routingKeys?: string[];
  /** Optional array of accepted message types */
  accept?: string[];
}

/**
 * Represents a DIDComm message.
 * This is the core message format used for all DIDComm communications.
 */
export interface Message {
  /** Unique identifier for this message */
  id: string;
  /** The protocol and message type (e.g., 'https://didcomm.org/basicmessage/2.0/message') */
  type: string;
  /** The message content/payload */
  body: Record<string, unknown>;
  /** The sender's DID (optional for anonymous messages) */
  from?: string;
  /** Array of recipient DIDs */
  to?: string[];
  /** Unix timestamp when the message was created */
  created_time?: number;
  /** Unix timestamp when the message expires */
  expires_time?: number;
  /** Optional array of attachments */
  attachments?: Attachment[];
}

/**
 * Represents an attachment to a DIDComm message.
 * Attachments can contain various types of data in different formats.
 */
export interface Attachment {
  /** Unique identifier for this attachment */
  id: string;
  /** Optional MIME type of the attachment content */
  media_type?: string;
  /** The actual attachment data */
  data: AttachmentData;
}

/**
 * Represents the data of an attachment in various formats.
 * This allows for flexible handling of different types of attachment content.
 */
export interface AttachmentData {
  /** JSON data */
  json?: unknown;
  /** Base64-encoded binary data */
  base64?: string;
  /** Array of URLs pointing to the data */
  links?: string[];
  /** JWS data for signed attachments */
  jws?: string;
  /** Hash of the data for integrity verification */
  hash?: string;
}

/**
 * Configuration options for the DIDComm client.
 */
export interface DIDCommConfig {
  /** The default packing type to use when not specified in operations */
  defaultPacking: PackingType;
  /** Maximum allowed message size in bytes */
  maxMessageSize?: number;
  /** Whether to use HTTPS for transport */
  useHttps?: boolean;
  /** Custom HTTP headers to include in requests */
  headers?: Record<string, string>;
}

/**
 * Generic result type for DIDComm operations.
 * Provides a consistent way to handle both successful and failed operations.
 */
export interface DIDCommResult<T> {
  /** Whether the operation was successful */
  success: boolean;
  /** The result data if successful */
  data?: T;
  /** Error information if unsuccessful */
  error?: {
    /** Error code for programmatic handling */
    code: string;
    /** Human-readable error message */
    message: string;
  };
}

/**
 * Options for encrypting a DIDComm message.
 */
export interface EncryptOptions {
  /** Array of recipient DIDs */
  to: string[];
  /** The sender's DID (required for authenticated encryption) */
  from?: string;
  /** The packing algorithm to use */
  packing?: PackingType;
  /** Whether to sign the message before encrypting */
  sign?: boolean;
}

/**
 * Options for signing a DIDComm message.
 */
export interface SignOptions {
  /** The signer's DID */
  from: string;
  /** Whether to protect the sender's identity in the signature */
  protectSenderIdentity?: boolean;
}

/**
 * Options for decrypting a DIDComm message.
 */
export interface DecryptOptions {
  /** The recipient's DID to decrypt for */
  recipient?: string;
  /** Whether to verify the signature if present */
  verifySignature?: boolean;
}
