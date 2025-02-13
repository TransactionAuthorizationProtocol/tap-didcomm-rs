/**
 * Core types for the DIDComm TypeScript implementation.
 * @module
 */

/**
 * Supported packing algorithms for DIDComm messages.
 */
export enum PackingType {
  /** No encryption, just signing */
  SIGNED = 'signed',
  /** Anonymous encryption */
  ANONCRYPT = 'anoncrypt',
  /** Authenticated encryption */
  AUTHCRYPT = 'authcrypt',
}

/**
 * A DID Document as defined in the DID Core specification.
 */
export interface DIDDocument {
  /** The DID that identifies this DID Document */
  id: string;
  /** The verification methods associated with this DID */
  verificationMethod?: VerificationMethod[];
  /** Authentication verification methods */
  authentication?: string[];
  /** Key agreement verification methods */
  keyAgreement?: string[];
  /** Assertion method verification methods */
  assertionMethod?: string[];
  /** Service endpoints */
  service?: ServiceEndpoint[];
}

/**
 * A verification method in a DID Document.
 */
export interface VerificationMethod {
  /** The ID of this verification method */
  id: string;
  /** The type of the verification method */
  type: string;
  /** The controller of this verification method */
  controller: string;
  /** The public key material */
  publicKeyJwk?: JsonWebKey;
  /** Multibase-encoded public key */
  publicKeyMultibase?: string;
}

/**
 * A service endpoint in a DID Document.
 */
export interface ServiceEndpoint {
  /** The ID of this service */
  id: string;
  /** The type of service */
  type: string;
  /** The endpoint URL */
  serviceEndpoint: string;
  /** Optional routing keys */
  routingKeys?: string[];
  /** Optional acceptance criteria */
  accept?: string[];
}

/**
 * A DIDComm message.
 */
export interface Message {
  /** The unique ID of this message */
  id: string;
  /** The type of this message */
  type: string;
  /** The message body */
  body: Record<string, unknown>;
  /** The sender's DID */
  from?: string;
  /** The recipient DIDs */
  to?: string[];
  /** When the message was created */
  created_time?: number;
  /** When the message expires */
  expires_time?: number;
  /** Message attachments */
  attachments?: Attachment[];
}

/**
 * A message attachment.
 */
export interface Attachment {
  /** The ID of this attachment */
  id: string;
  /** The MIME type of the attachment */
  media_type?: string;
  /** The attachment data */
  data: AttachmentData;
}

/**
 * Attachment data formats.
 */
export interface AttachmentData {
  /** JSON data */
  json?: unknown;
  /** Base64-encoded data */
  base64?: string;
  /** External link */
  links?: string[];
  /** JWS data */
  jws?: string;
  /** Hash of the data */
  hash?: string;
}

/**
 * Configuration for DIDComm operations.
 */
export interface DIDCommConfig {
  /** Default packing type to use */
  defaultPacking: PackingType;
  /** Maximum message size in bytes */
  maxMessageSize?: number;
  /** Whether to use HTTPS for transport */
  useHttps?: boolean;
  /** Custom HTTP headers */
  headers?: Record<string, string>;
}

/**
 * Result of a DIDComm operation.
 */
export interface DIDCommResult<T> {
  /** Whether the operation was successful */
  success: boolean;
  /** The result data if successful */
  data?: T;
  /** Error information if unsuccessful */
  error?: {
    /** Error code */
    code: string;
    /** Error message */
    message: string;
  };
}

/**
 * Options for encrypting a message.
 */
export interface EncryptOptions {
  /** The recipient DIDs */
  to: string[];
  /** The sender DID (for authcrypt) */
  from?: string;
  /** The packing algorithm to use */
  packing?: PackingType;
  /** Whether to sign the message before encrypting */
  sign?: boolean;
}

/**
 * Options for signing a message.
 */
export interface SignOptions {
  /** The signer's DID */
  from: string;
  /** Whether to protect the sender's identity */
  protectSenderIdentity?: boolean;
}

/**
 * Options for decrypting a message.
 */
export interface DecryptOptions {
  /** The recipient's DID to decrypt for */
  recipient?: string;
  /** Whether to verify the signature if present */
  verifySignature?: boolean;
}
