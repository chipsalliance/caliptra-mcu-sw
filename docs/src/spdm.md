# SPDM
The Security Protocol and Data Model (SPDM) is a protocol designed to ensure secure communication between hardware components by focusing on mutual authentication and the establishment of secure channels over potentially insecure media. SPDM enables devices to verify each other's identities and configurations, leveraging X.509v3 certificates to ensure cryptographic security. Designed for interoperability, it can work across various transport and physical media, often utilizing the Management Component Transport Protocol (MCTP). This protocol is especially valuable in environments where secure hardware communication is crucial, such as data centers and enterprise systems.

## Specifications
| Specification                                 | Document Link                                                                             |
| --------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Security Protocol and Data Model              | [DSP0274](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.3.2.pdf) |
| Secured Messages using SPDM                   | [DSP0277](https://www.dmtf.org/sites/default/files/standards/documents/DSP0277_1.2.0.pdf) |
| SPDM over MCTP Binding Specification          | [DSP0275](https://www.dmtf.org/sites/default/files/standards/documents/DSP0275_1.0.2.pdf) |
| Secured Messages using SPDM over MCTP Binding | [DSP0276](https://www.dmtf.org/sites/default/files/standards/documents/DSP0276_1.2.0.pdf) |

## SPDM Protocol Sequence
```mermaid
sequenceDiagram
    participant Requester
    participant Responder

    Requester->>Responder: GetVersion
    Responder-->>Requester: Version
    Requester->>Responder: GetCapabilities
    Responder-->>Requester: Capabilities
    Requester->>Responder: NegotiateAlgorithms
    Responder-->>Requester: Algorithms
    opt If supported
        Requester->>Responder: GetDigests
        Responder-->>Requester: Digests
    end
    opt If needed
        Requester->>Responder: GetCertificate
        Responder-->>Requester: Certificate
    end
    opt If supported
        Requester->>Responder: Challenge
        Responder-->>Requester: ChallengeAuth
    end
    opt If supported
        Requester->>Responder: GetMeasurements
        Responder-->>Requester: Measurements
    end
    opt If supported
        Requester->>Responder: KeyExchange
        Responder-->>Requester: KeyExchangeRsp
    end
    rect rgb(255, 255, 204)
        note right of Requester: Secure Session
        opt If supported
            Requester->>Responder: Finish
            Responder-->>Requester: FinishRsp
        end
    end
```

## Class Diagram

```mermaid
classDiagram
    direction RL
    MCTP Transport <|--|> SpdmContext: processRequest() / sendResponse()
    SecureSessionMgr <|-- SpdmContext: processSecureMessage()
    TranscriptMgr <|-- SpdmContext
    TranscriptMgr <|-- SecureSessionMgr
    class SpdmContext{
      - transcriptMgr
      - sessionMgr
      + processRequest()
      + sendResponse()
    }
    class SecureSessionMgr {
      -transcriptMgr
      +TraitMethods
    }
    class TranscriptMgr{
      +TraitMethods
    }
```

## SPDM Responder
The Responder is responsible for receiving and processing requests from the Requestor. It authenticates the Requestor's identity, attests its own state and configuration, and establishes a secure communication channel. The Responder uses cryptographic techniques, such as validating X.509v3 certificates, to ensure the integrity and confidentiality of the exchanged data.

### Responder supported messages
The SPDM Responder supports the following messages:

| Message            | Description                                                                     |
| ------------------ | ------------------------------------------------------------------------------- |
| `VERSION`          | Retrieves version information                                                   |
| `CAPABILITIES`     | Retrieves SPDM capabilities                                                     |
| `ALGORITHMS`       | Retrieves the negotiated algorithms                                             |
| `DIGESTS`          | Retrieves digest of the certificate chains                                      |
| `CERTIFICATE`      | Retrieves certificate chains                                                    |
| `MEASUREMENTS`     | Retrieves measurements of elements such as intenral state                       |
| `KEY_EXCHANGE_RSP` | Retrieves the responder's public key information                                |
| `FINISH_RSP`       | Provide key confirmation, bind the identity of each party to the exchanged keys |
| `END_SESSION_ACK`  | End session acknowledgment                                                      |
| `ERROR`            | Error message                                                                   |


### Responder Interface
```Rust
pub struct SpdmContext<T: MctpTransport, U: SpdmTranscriptManager, V: SpdmSecureSessionManager> {
    transport: T,
    transcript_manager: U,
    session_manager: V,
    data_buffer: [u8; MAX_SPDM_MESSAGE_SIZE],
}

impl<T: MctpTransport, U: SpdmTranscriptManager, V: SpdmSecureSessionManager> SpdmContext<T, U, V> {
    pub fn new(transport: T, transcript_manager: U, session_manager: V) -> Self {
        SpdmContext {
            transport,
            transcript_manager,
            session_manager,
            data_buffer: [0; MAX_SPDM_MESSAGE_SIZE],
        }
    }

    pub async fn handle_request(&mut self, request_info: u32) {
        // request_info: Bits[16:23] Message Type [SPDM | Secure SPDM]
    }
}

```

## Transcript Manager
The Transcript Manager is for managing the transcript and the transcript hash. The transcript is a sequential concatenation of prescribed full messages or message fields. The transcript hash is the cryptographic hash of this transcript, computed using the negotiated hash algorithm. This component ensures the integrity and authenticity of SPDM communications by managing these essential elements.

### Transcript Manager Interface
```Rust
pub trait SpdmTranscriptManager {
    /// Set the hash algorithm. The algorithm can be set only once.
    ///
    /// # Parameters
    /// - `hash_algo`: Hash algorithm to set.
    ///
    /// # Returns
    /// - `Result<(), SpdmError>`: Returns `Ok(())` if the hash algorithm was set, or an error code.
    fn set_hash_algo(&self, hash_algo: HashType) -> Result<(), SpdmError>;

    /// Set the SPDM negotiated version to be used for communication.
    ///
    /// # Parameters
    /// - `spdm_version`: SPDM negotiated version.
    fn set_spdm_version(&self, spdm_version: u8);

    /// Update the transcript with a message.
    ///
    /// # Parameters
    /// - `context_type`:        Transcript context to update.
    /// - `message`:             Message to add to the transcript.
    /// - `use_session_context`: Use session context to update an SPDM session transcript.
    /// - `session_idx`:         SPDM session index.
    ///
    /// # Returns
    /// - `Result<(), SpdmError>`:
    /// Returns `Ok(())` if the message was added to the transcript successfully, or an error code.
    async fn update(
        &self,
        context_type: SpdmTranscriptManagerContextType, // [VCA, M1M2, L1L2, TH]
        message: &[u8],
        use_session_context: bool,
        session_idx: u8,
    ) -> Result<(), SpdmError>;

    /// Get the hash based on the hash type. The hashing operation is finished if `finish_hash` is set
    /// to `true`. In that case, an additional call to update will start a new hashing operation.
    /// If `finish_hash` is set to `false`, the hash is not finalized and can be updated with additional
    /// calls to update.
    ///
    /// # Parameters
    /// - `context_type`:        Transcript context type to get the hash from.
    /// - `finish_hash`:         Flag to indicate to finish the hash.
    /// - `use_session_context`: Use session context to update an SPDM session transcript.
    /// - `session_idx`:         SPDM session index.
    /// - `hash`:                Buffer to copy the hash to.
    ///
    /// # Returns
    /// - `Result<Vec<u8>, SpdmError>`: Returns the hash if the operation was successful, or an error code.
    fn get_hash(
        &self,
        context_type: SpdmTranscriptManagerContextType, // [VCA, M1M2, L1L2, TH]
        finish_hash: bool,
        use_session_context: bool,
        session_idx: u8,
        hash: &mut [u8]
    ) -> Result<(), SpdmError>;

    /// Reset a transcript context.
    ///
    /// # Parameters
    /// - `context_type`:        Transcript context to reset.
    /// - `use_session_context`: Use session context to update an SPDM session transcript.
    /// - `session_idx`:         SPDM session index.
    fn reset_transcript(
        &self,
        context_type: SpdmTranscriptManagerContextType, // [VCA, M1M2, L1L2, TH]
        use_session_context: bool,
        session_idx: u8,
    );
}
```

## SPDM Secure Session Manager
The SPDM Secure Session Manager is responsible for managing secure sessions within the SPDM protocol framework. It provides mechanisms to create, release, and retrieve secure sessions. The manager can set and query the state of a session, ensuring secure communication between devices. It generates necessary cryptographic keys, including shared secrets, handshake keys, and data keys, through asynchronous methods. Additionally, it verifies the integrity and optionally decrypts secure messages, and encodes messages with appropriate security measures. The manager also tracks session validity and can reset session states and identifiers as needed, ensuring robust and secure session management.

### Secure Session Manager Interface
```Rust
pub trait SpdmSecureSessionManager {
    /// Create a new SPDM secure session.
    ///
    /// # Parameters
    /// - `session_id`:      Session Id for the session.
    /// - `is_requester`:    True if the session is for the requester, false otherwise.
    /// - `connection_info`: SPDM connection info.
    ///
    /// # Returns
    /// - `Option<&SpdmSecureSession>`:
    ///    A pointer to the created SPDM secure session or `None` if the session could not be created.
    fn create_session(
        &self,
        session_id: u32,
        is_requester: bool,
        connection_info: &SpdmConnectionInfo,
    ) -> Result<&SpdmSecureSession, SpdmError>;


    /// Release an SPDM secure session.
    ///
    /// # Parameters
    /// - `session_id`: Session Id for the session.
    fn release_session(&self, session_id: u32);

    /// Get an SPDM secure session.
    ///
    /// # Parameters
    /// - `session_id`: Session Id for the session.
    ///
    /// # Returns
    /// - `Option<&SpdmSecureSession>`: A pointer to the SPDM secure session or `None` if the session does not exist.
    fn get_session(& self, session_id: u32) -> Option<& SpdmSecureSession>;

    /// Set the session state for an SPDM secure session.
    ///
    /// # Parameters
    /// - `session_id`:    Session Id for the session.
    /// - `session_state`: Session state to set.
    fn set_session_state(&self, session_id: u32, session_state: SpdmSecureSessionState);

    /// Reset the Session Manager.
    fn reset(&self);

    /// Generate the shared secret from peer and local public keys.
    ///
    /// # Parameters
    /// - `session`:            SPDM session info.
    /// - `peer_pub_key_point`: Peer public key in point format.
    /// - `local_public_key`: Generated local public key in point format on return.
    ///
    /// # Returns
    /// - `Result<(), SpdmError>`:
    ///    Returns the local public key in point format if the shared secret is generated successfully, or an error code.
    fn generate_shared_secret(
        &self,
        session: &SpdmSecureSession,
        peer_pub_key_point: &EccPointPublicKey,
        local_public_key: &mut [u8]
    ) -> Result<(), SpdmError>;

    /// Generate handshake keys for an SPDM secure session.
    ///
    /// # Parameters
    /// - `session`: Secure Session.
    ///
    /// # Returns
    /// - `Result<(), SpdmError>`: Returns `Ok(())` if the handshake keys are generated successfully, or an error code.
    async fn generate_session_handshake_keys(&self, session: &mut SpdmSecureSession) -> Result<(), SpdmError>;

    /// Generate data keys for an SPDM secure session.
    ///
    /// # Parameters
    /// - `session`: SPDM Secure Session.
    ///
    /// # Returns
    /// - `Result<(), SpdmError>`: Returns `Ok(())` if the data keys are generated successfully, or an error code.
    async fn generate_session_data_keys(&self, session: &mut SpdmSecureSession) -> Result<(), SpdmError>;

    /// Query if the last session is active.
    ///
    /// # Returns
    /// - `bool`: True if the last session is active, false otherwise.
    fn is_last_session_id_valid(&self) -> bool;

    /// Get the last session id.
    ///
    /// # Returns
    /// - `u32`: Last session id.
    fn get_last_session_id(&self) -> u32;

    /// Reset the last session id validity.
    fn reset_last_session_id_validity(&self);

    /// Decode a secure message. This includes MAC verification and optionally decryption.
    ///
    /// # Parameters
    /// - `request`: SPDM request message to be decoded.
    ///
    /// # Returns
    /// - `Result<(), SpdmError>`: Returns `Ok(())` if the secure message is decoded successfully, or an error code.
    async fn decode_secure_message(&self, request: &mut [u8]) -> Result<(), SpdmError>;

    /// Encode a secure message. This includes MAC generation and optionally encryption.
    ///
    /// # Parameters
    /// - `response`: SPDM response message to be encoded.
    ///
    /// # Returns
    /// - `Result<(), SpdmError>`: Returns `Ok(())` if the secure message is encoded successfully, or an error code.
    async fn encode_secure_message(&self, response: &mut [u8]) -> Result<(), SpdmError>;
}
```

## Certificate Slot Management Structures

TBD

```rust
struct BankElement {
    asym_algo: AsymAlgo, //Either ECCP384 or ML-DSA-87
    bank_id: u8, //Bank ID. Default 0 for ECCP384, 1 for ML-DSA-87
    supported_slot_mask: u8, // SPDM slot mask for Vendor(0), Owner and Tenant entities 
    mutable_slot_elements: [Option<MutSlotElement>; MAX_SLOTS_PER_BANK], // Min of 2 mutable slots, max of 8 slots. Some if provisioned, None if not.
}

struct MutSlotElement {
    slot_id: u8, // Slot ID.
    slot_attr: SlotAttr, // Slot attributes.
    key_pair_id: u8, // Key pair ID. Anchored key pair ID for slot after provisioning. 
    certificate_info: CertificateInfo, // Certificate model used for this slot.
    key_usage: KeyUsage, // Key usage for this slot.
    slot_size: u32, // Number of bytes available for cert chain storage in this slot. (min 1 cert size)
    cert_chain: CertChain, // Certificate chain for this slot.
}

bitfield! {
    pub struct SlotAttr(u8);
    impl Debug;
    u8;
    pub provisioned, set_provisioned: 0, 0; // Bit[0]:Provisioned  // Slot 0 is always provisioned
    pub write_protected, set_write_protected: 6, 6; // Bit[1]: Write Protected // Slot 0 is always write protected
}

/// Generic certificate chain that combines all certificate components
pub struct CertChain {
    endorsement_cert_chain: &'static mut dyn EndorsementCertChainTrait,
    dpe_cert_chain: DpeCertChain,
    leaf_cert: DpeLeafCert,
}
```

## Integration guide
The following sections provide guidance on integrating the SPDM Responder with integrator's specific configurations and implementations.

### Certificate Store
The integrator is responsible for implementing the certificate store. The certificate store provides persistent storage for the certificate chains associated with each certificate slot. To enable this functionality, the integrator shall implement the `SpdmCertStore` trait, which defines the required operations for reading, writing, and managing the SPDM certificate chains.

```rust
pub enum ProvisioningEntityType {
    Vendor,
    Owner,
    Tenant,
}

pub struct SlotInfo {
    pub slot_id: u8,
    pub prov_entity_type: ProvisioningEntityType,
    pub provisioned: bool,
    pub session_needed: bool,
    // Additional fields can be added as needed
}

pub struct DeviceKeyPairInfo {
    pub key_pair_id: u8,
    pub key_capabilities: KeyCapabilities,
    pub key_usage: KeyUsageMask,
}
enum CsrType {
    Csr,
    EnvelopeSignedCsr,
}


pub trait SpdmCertStore {
    /// Get supported certificate slot count
    /// The supported slots are consecutive from 0 to slot_count - 1.
    ///
    /// # Returns
    /// * `u8` - The number of supported certificate slots.
    fn slot_count(&self) -> u8;

    /// Check if the slot is provisioned.
    ///
    /// # Arguments
    /// * `slot_id` - The slot ID of the certificate chain.
    ///
    /// # Returns
    /// * `bool` - True if the slot is provisioned, false otherwise.
    async fn is_provisioned(&self, slot_id: u8) -> bool;

    /// Get the hash of the root certificate in the certificate chain.
    /// The hash algorithm is always SHA-384. The type of the certificate chain is indicated by the asym_algo parameter.
    ///
    /// # Arguments
    /// * `asym_algo` - The asymmetric algorithm to indicate the type of Certificate chain.
    /// * `slot_id` - The slot ID of the certificate chain.
    /// * `cert_hash` - The buffer to store the hash of the root certificate.
    ///
    /// # Returns
    /// * `()` - Ok if successful, error otherwise.
    async fn root_cert_hash<'a>(
        &self,
        asym_algo: AsymAlgo,
        slot_id: u8,
        cert_hash: &'a mut [u8; SHA384_HASH_SIZE],
    ) -> CertStoreResult<()>;

    /// Get the length of the certificate chain in bytes.
    /// The certificate chain is in ASN.1 DER-encoded X.509 v3 format.
    /// The type of the certificate chain is indicated by the asym_algo parameter.
    ///
    /// # Arguments
    /// * `slot_id` - The slot ID of the certificate chain.
    /// * `asym_algo` - The asymmetric algorithm to indicate the type of certificate chain.
    ///
    /// # Returns
    /// * `usize` - The length of the certificate chain in bytes or error.
    async fn cert_chain_len(&self, asym_algo: AsymAlgo, slot_id: u8) -> CertStoreResult<usize>;

    /// Reads the certificate chain in portion. The certificate chain is in ASN.1 DER-encoded X.509 v3 format.
    /// The type of the certificate chain is indicated by the asym_algo parameter.
    ///
    /// # Arguments
    /// * `asym_algo` - The asymmetric algorithm to indicate the type of Certificate chain.
    /// * `slot_id` - The slot ID of the certificate chain.
    /// * `offset` - The offset in bytes to start reading from.
    /// * `cert_portion` - The buffer to read the certificate chain into.
    ///
    /// # Returns
    /// * `usize` - The number of bytes read or error.
    /// If the cert portion size is smaller than the buffer size, the remaining bytes in the buffer will be filled with 0,
    /// indicating the end of the cert chain.
    async fn read_cert_chain<'a>(
        &self,
        asym_algo: AsymAlgo,
        slot_id: u8,
        offset: usize,
        cert_portion: &'a mut [u8],
    ) -> CertStoreResult<usize>;

    /// Reads the CSR/envelope signed CSR in portion.
    /// 
    /// # Arguments
    /// * `csr_type` - The type of CSR to be generated (CSR or Envelope Signed CSR).
    /// * `asym_algo` - The asymmetric algorithm to indicate the type of CSR.
    /// * `key_pair_id` - The key pair ID of the device key pair to
    /// * `nonce` - The nonce used in the CSR generation.
    /// * `csr_portion` - The buffer to read the CSR/envelope signed CSR into.
    /// 
    /// # Returns
    /// * `usize` - The total size or number of bytes read or error.
    /// When `csr_portion` is `None`, it returns the total size of the CSR/envelope signed CSR.
    /// When `csr_portion` is `Some`, it fills the provided buffer with the CSR/envelope signed CSR data
    /// If the CSR/envelope signed CSR size is smaller than the buffer size, the remaining bytes in the buffer will be filled with 0,
    /// indicating the end of the CSR/envelope signed CSR.
    async fn read_csr<'a>(&self, csr_type: CsrType, asym_algo: AsymAlgo, key_pair_id: u8, nonce: &[u8], csr_portion: Option<&'a mut [u8]>) -> CertStoreResult<usize>;

    /// Starts to write the certificate chain in ASN.1 DER-encoded X.509 v3 format in portions.
    /// 
    /// # Arguments
    /// * `asym_algo` - The asymmetric algorithm to indicate the type of Certificate chain.
    /// * `slot_id` - The slot ID of the certificate chain.
    /// * `total_len` - The total length of the certificate chain in bytes.
    /// * `cert_portion` - Optional portion of the certificate chain at the beginning to write.
    /// # Returns
    /// * `()` - Ok if successful, error otherwise.
    async fn write_cert_chain_start(&self, asym_algo: AsymAlgo, slot_id: u8, key_pair_id : u8, total_len: usize, cert_portion: Option<&[u8]>) -> CertStoreResult<()>;

    /// Continues to write the certificate chain in ASN.1 DER-encoded X.509 v3 format in portions.
    /// # Arguments
    /// * `asym_algo` - The asymmetric algorithm to indicate the type of Certificate chain.
    /// * `slot_id` - The slot ID of the certificate chain.
    /// * `cert_portion` - The portion of the certificate chain to write.
    /// # Returns
    /// * `()` - Ok if successful, error otherwise.
    async fn write_cert_chain_continue(&self, asym_algo: AsymAlgo, slot_id: u8, cert_portion: &[u8]) -> CertStoreResult<()>;

    /// Finishes writing the certificate chain in ASN.1 DER-encoded X.509 v3 format.
    /// # Arguments
    /// * `asym_algo` - The asymmetric algorithm to indicate the type of Certificate chain
    /// * `slot_id` - The slot ID of the certificate chain.
    /// # Returns
    /// * `()` - Ok if successful, error otherwise.
    async fn write_cert_chain_finish(&self, asym_algo: AsymAlgo, slot_id: u8) -> CertStoreResult<()>;

    /// Erase the certificate chain in the given slot.
    /// 
    /// # Arguments
    /// * `asym_algo` - The asymmetric algorithm to indicate the type of Certificate chain.
    /// * `slot_id` - The slot ID of the certificate chain.
    /// # Returns
    /// * `()` - Ok if successful, error otherwise.
    async fn erase_cert_chain(&self, asym_algo: AsymAlgo, slot_id: u8) -> CertStoreResult<()>;

    /// Sign hash with leaf certificate key
    ///
    /// # Arguments
    /// * `asym_algo` - Asymmetric algorithm to sign with.
    /// * `slot_id` - The slot ID of the certificate chain.
    /// * `hash` - The hash to sign.
    /// * `signature` - The output buffer to store the ECC384 signature.
    ///
    /// # Returns
    /// * `()` - Ok if successful, error otherwise.
    async fn sign_hash<'a>(
        &self,
        asym_algo: AsymAlgo,
        slot_id: u8,
        hash: &'a [u8; SHA384_HASH_SIZE],
        signature: &'a mut [u8; ECC_P384_SIGNATURE_SIZE],
    ) -> CertStoreResult<()>;

    /// Get the KeyPairID associated with the certificate chain if SPDM responder supports
    /// multiple assymmetric keys in connection.
    ///
    /// # Arguments
    /// * `slot_id` - The slot ID of the certificate chain.
    ///
    /// # Returns
    /// * u8 - The KeyPairID associated with the certificate chain or None if not supported or not found.
    async fn key_pair_id(&self, slot_id: u8) -> Option<u8>;

    /// Retrieve the `CertificateInfo` associated with the certificate chain for the given slot.
    /// The `CertificateInfo` structure specifies the certificate model (such as DeviceID, Alias, or General),
    /// and includes reserved bits for future extensions.
    ///
    /// # Arguments
    /// * `slot_id` - The slot ID of the certificate chain.
    ///
    /// # Returns
    /// * `CertificateInfo` - The CertificateInfo associated with the certificate chain or None if not supported or not found.
    async fn cert_info(&self, slot_id: u8) -> Option<CertificateInfo>;

    /// Get the KeyUsageMask associated with the certificate chain if SPDM responder supports
    /// multiple asymmetric keys in connection.
    ///
    /// # Arguments
    /// * `slot_id` - The slot ID of the certificate chain.
    ///
    /// # Returns
    /// * `KeyUsageMask` - The KeyUsageMask associated with the certificate chain or None if not supported or not found.
    async fn key_usage_mask(&self, slot_id: u8) -> Option<KeyUsageMask>;
}

```