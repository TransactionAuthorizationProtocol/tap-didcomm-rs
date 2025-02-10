//! HTTP endpoint handlers.

use actix_web::{get, post, web, HttpResponse};
use serde::{Deserialize, Serialize};
use tap_didcomm_core::types::{Message, PackedMessage, PackingType};
use tap_didcomm_node::{dispatch_message, DispatchOptions, DIDCommNode};
use tracing::{debug, info};

use crate::error::{Error, Result};

/// Request body for sending a message.
#[derive(Debug, Deserialize)]
pub struct SendMessageRequest {
    /// The message to send.
    pub message: Message,
    /// The packing type to use.
    #[serde(default)]
    pub packing: Option<PackingType>,
    /// The endpoint to send the message to.
    pub endpoint: String,
}

/// Response body for node status.
#[derive(Debug, Serialize)]
pub struct NodeStatus {
    /// The node's DID.
    pub did: String,
    /// The node's base URL.
    pub base_url: Option<String>,
    /// Whether the node is ready to receive messages.
    pub ready: bool,
}

/// Handles incoming DIDComm messages.
///
/// # Arguments
///
/// * `node` - The DIDComm node
/// * `message` - The packed message
#[post("/didcomm")]
pub async fn receive_message(
    node: web::Data<DIDCommNode>,
    message: web::Json<PackedMessage>,
) -> Result<HttpResponse> {
    info!("Received DIDComm message");
    debug!("Message: {:?}", message);

    // Process the message
    node.receive(&serde_json::to_string(&message.0).map_err(Error::Serialization)?)
        .await
        .map_err(Error::Node)?;

    Ok(HttpResponse::Ok().finish())
}

/// Sends a DIDComm message.
///
/// # Arguments
///
/// * `node` - The DIDComm node
/// * `request` - The send message request
#[post("/didcomm/send")]
pub async fn send_message(
    node: web::Data<DIDCommNode>,
    request: web::Json<SendMessageRequest>,
) -> Result<HttpResponse> {
    info!("Sending DIDComm message");
    debug!("Request: {:?}", request);

    // Get the packing type
    let packing = request.packing.unwrap_or(node.config().default_packing);

    // Create dispatch options
    let options = DispatchOptions {
        packing,
        endpoint: request.endpoint.clone(),
    };

    // Dispatch the message
    dispatch_message(&request.message, node.plugin(), options)
        .await
        .map_err(Error::Node)?;

    Ok(HttpResponse::Ok().finish())
}

/// Returns the node's status.
///
/// # Arguments
///
/// * `node` - The DIDComm node
#[get("/status")]
pub async fn get_status(node: web::Data<DIDCommNode>) -> Result<HttpResponse> {
    info!("Getting node status");

    let status = NodeStatus {
        did: node.config().did.clone(),
        base_url: node.config().base_url.clone(),
        ready: true,
    };

    Ok(HttpResponse::Ok().json(status))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App};
    use serde_json::json;
    use tap_didcomm_core::Message as CoreMessage;
    use tap_didcomm_node::NodeConfig;

    // Mock plugin (same as in node tests)
    struct MockPlugin;

    #[async_trait::async_trait]
    impl tap_didcomm_core::plugin::DIDResolver for MockPlugin {
        async fn resolve(&self, _did: &str) -> tap_didcomm_core::error::Result<serde_json::Value> {
            Ok(json!({}))
        }
    }

    #[async_trait::async_trait]
    impl tap_didcomm_core::plugin::Signer for MockPlugin {
        async fn sign(
            &self,
            message: &[u8],
            _from: &str,
        ) -> tap_didcomm_core::error::Result<Vec<u8>> {
            Ok(message.to_vec())
        }

        async fn verify(&self, _message: &[u8], _from: &str) -> tap_didcomm_core::error::Result<()> {
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl tap_didcomm_core::plugin::Encryptor for MockPlugin {
        async fn encrypt(
            &self,
            message: &[u8],
            _to: &[String],
            _from: Option<&str>,
        ) -> tap_didcomm_core::error::Result<PackedMessage> {
            Ok(PackedMessage {
                data: String::from_utf8(message.to_vec()).unwrap(),
                packing: self.packing_type(),
            })
        }

        async fn decrypt(
            &self,
            message: &PackedMessage,
            _to: &str,
        ) -> tap_didcomm_core::error::Result<Vec<u8>> {
            Ok(message.data.as_bytes().to_vec())
        }

        fn packing_type(&self) -> PackingType {
            PackingType::Plain
        }
    }

    impl tap_didcomm_core::plugin::DIDCommPlugin for MockPlugin {
        fn as_resolver(&self) -> &dyn tap_didcomm_core::plugin::DIDResolver {
            self
        }

        fn as_signer(&self) -> &dyn tap_didcomm_core::plugin::Signer {
            self
        }

        fn as_encryptor(&self) -> &dyn tap_didcomm_core::plugin::Encryptor {
            self
        }
    }

    #[actix_rt::test]
    async fn test_receive_message() {
        // Create a test app
        let node = DIDCommNode::new(
            NodeConfig {
                did: "did:example:node".into(),
                default_packing: PackingType::Plain,
                base_url: None,
            },
            MockPlugin,
        );

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(node))
                .service(receive_message),
        )
        .await;

        // Create a test message
        let message = CoreMessage::new("test", json!({"hello": "world"}))
            .unwrap()
            .to(vec!["did:example:node"]);

        let packed = tap_didcomm_core::pack::pack_message(&message, &MockPlugin, PackingType::Plain)
            .await
            .unwrap();

        // Send the request
        let req = test::TestRequest::post()
            .uri("/didcomm")
            .set_json(&packed)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[actix_rt::test]
    async fn test_get_status() {
        // Create a test app
        let node = DIDCommNode::new(
            NodeConfig {
                did: "did:example:node".into(),
                default_packing: PackingType::Plain,
                base_url: Some("http://localhost:8080".into()),
            },
            MockPlugin,
        );

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(node))
                .service(get_status),
        )
        .await;

        // Send the request
        let req = test::TestRequest::get().uri("/status").to_request();

        let resp: NodeStatus = test::call_and_read_body_json(&app, req).await;
        assert_eq!(resp.did, "did:example:node");
        assert_eq!(resp.base_url, Some("http://localhost:8080".into()));
        assert!(resp.ready);
    }
} 