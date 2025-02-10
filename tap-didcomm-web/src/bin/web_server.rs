use tap_didcomm_core::plugin::{DIDCommPlugin, DIDResolver, Encryptor, Signer};
use tap_didcomm_web::server::{CorsConfig, ServerConfig, DIDCommServer};
use base64::{Engine, engine::general_purpose::STANDARD};

struct TestPlugin;

#[async_trait::async_trait]
impl DIDResolver for TestPlugin {
    async fn resolve(&self, _did: &str) -> tap_didcomm_core::error::Result<String> {
        Ok("{}".to_string())
    }
}

#[async_trait::async_trait]
impl Signer for TestPlugin {
    async fn sign(
        &self,
        message: &[u8],
        _from: &str,
    ) -> tap_didcomm_core::error::Result<Vec<u8>> {
        // For testing, we'll just base64 encode the message
        Ok(STANDARD.encode(message).into_bytes())
    }

    async fn verify(
        &self,
        _message: &[u8],
        _signature: &[u8],
        _from: &str,
    ) -> tap_didcomm_core::error::Result<bool> {
        Ok(true)
    }
}

#[async_trait::async_trait]
impl Encryptor for TestPlugin {
    async fn encrypt(
        &self,
        message: &[u8],
        _to: Vec<String>,
        _from: Option<String>,
    ) -> tap_didcomm_core::error::Result<Vec<u8>> {
        // For testing, we'll just base64 encode the message
        Ok(STANDARD.encode(message).into_bytes())
    }

    async fn decrypt(
        &self,
        message: &[u8],
        _recipient: String,
    ) -> tap_didcomm_core::error::Result<Vec<u8>> {
        // For testing, we'll try to base64 decode the message
        if let Ok(decoded) = STANDARD.decode(message) {
            Ok(decoded)
        } else {
            // If not base64, return as is
            Ok(message.to_vec())
        }
    }
}

impl DIDCommPlugin for TestPlugin {
    fn as_resolver(&self) -> &dyn DIDResolver {
        self
    }

    fn as_signer(&self) -> &dyn Signer {
        self
    }

    fn as_encryptor(&self) -> &dyn Encryptor {
        self
    }
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    let config = ServerConfig {
        host: "127.0.0.1".to_string(),
        port: 8080,
        cors: CorsConfig {
            allowed_origins: vec!["*".to_string()],
            allow_credentials: true,
        },
    };

    let node_config = tap_didcomm_node::NodeConfig::default();
    let plugin = TestPlugin;

    let server = DIDCommServer::new(config, node_config, plugin);
    server.run().await.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    Ok(())
} 