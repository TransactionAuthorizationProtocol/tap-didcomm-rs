//! HTTP endpoint handlers.

use actix_web::{post, web, HttpResponse};
use serde::{Deserialize, Serialize};
use tap_didcomm_core::{Message, types::PackingType};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use log::{error, debug};

use crate::error::{Error, Result};

/// Request body for receiving a DIDComm message.
#[derive(Debug, Deserialize)]
pub struct ReceiveMessageRequest {
    /// The base64-encoded message data.
    pub data: String,
}

/// Request body for sending a DIDComm message.
#[derive(Debug, Deserialize)]
pub struct SendMessageRequest {
    /// The message to send.
    pub message: Message,
    /// The packing type to use.
    pub packing: PackingType,
    /// The endpoint to send the message to.
    pub endpoint: String,
}

/// Response body for the status endpoint.
#[derive(Debug, Serialize)]
pub struct StatusResponse {
    /// The status of the node.
    pub status: String,
}

/// Receives a DIDComm message.
#[post("/didcomm")]
pub async fn receive_message(
    request: web::Json<ReceiveMessageRequest>,
    node: web::Data<std::sync::Arc<std::sync::Mutex<tap_didcomm_node::DIDCommNode>>>,
) -> Result<HttpResponse> {
    debug!("Received message request: {:?}", request);
    
    let message_data = STANDARD.decode(&request.data)
        .map_err(|e| {
            error!("Failed to decode message: {}", e);
            Error::InvalidFormat(format!("Failed to decode message: {}", e))
        })?;

    let message_str = String::from_utf8(message_data)
        .map_err(|e| {
            error!("Failed to decode message as UTF-8: {}", e);
            Error::InvalidFormat(format!("Failed to decode message as UTF-8: {}", e))
        })?;

    let node = node.lock()
        .map_err(|e| {
            error!("Failed to lock node: {}", e);
            Error::Internal(format!("Failed to lock node: {}", e))
        })?;

    node.receive(&message_str).await
        .map_err(|e| {
            error!("Failed to handle message: {}", e);
            Error::Message(format!("Failed to handle message: {}", e))
        })?;

    Ok(HttpResponse::Ok().finish())
}

/// Sends a DIDComm message.
#[post("/didcomm/send")]
pub async fn send_message(
    request: web::Json<SendMessageRequest>,
    node: web::Data<std::sync::Arc<std::sync::Mutex<tap_didcomm_node::DIDCommNode>>>,
) -> Result<HttpResponse> {
    debug!("Sending message request: {:?}", request);
    
    let node = node.lock()
        .map_err(|e| {
            error!("Failed to lock node: {}", e);
            Error::Internal(format!("Failed to lock node: {}", e))
        })?;

    let _packed_message = tap_didcomm_core::pack::pack_message(
        &request.message,
        node.plugin(),
        request.packing,
    ).await
        .map_err(|e| {
            error!("Failed to pack message: {}", e);
            Error::Message(format!("Failed to pack message: {}", e))
        })?;

    // TODO: Send the message to the endpoint
    // For now, we'll just return success
    Ok(HttpResponse::Ok().finish())
}

/// Returns the status of the node.
#[post("/status")]
pub async fn status(
    node: web::Data<std::sync::Arc<std::sync::Mutex<tap_didcomm_node::DIDCommNode>>>,
) -> Result<HttpResponse> {
    debug!("Status request received");
    
    let _node = node.lock()
        .map_err(|e| {
            error!("Failed to lock node: {}", e);
            Error::Internal(format!("Failed to lock node: {}", e))
        })?;

    Ok(HttpResponse::Ok().json(StatusResponse {
        status: "ok".to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App};
    use tap_didcomm_node::NodeConfig;
    use crate::tests::MockPlugin;
    use serde_json::json;

    #[actix_rt::test]
    async fn test_receive_message() {
        let node_config = NodeConfig::default();
        let plugin = MockPlugin::new();
        let node = std::sync::Arc::new(std::sync::Mutex::new(
            tap_didcomm_node::DIDCommNode::new(node_config, plugin)
        ));
        let node_data = web::Data::new(node);

        let app = test::init_service(
            App::new()
                .app_data(node_data.clone())
                .service(receive_message)
        ).await;

        // Create a test message
        let message = Message::new("test", json!({"hello": "world"}))
            .unwrap()
            .from("did:example:alice")
            .to(vec!["did:example:bob"]);

        // Pack the message
        let node = node_data.lock().unwrap();
        let packed_message = tap_didcomm_core::pack::pack_message(
            &message,
            node.plugin(),
            PackingType::Signed,
        ).await.unwrap();
        drop(node);

        let req = test::TestRequest::post()
            .uri("/didcomm")
            .set_json(json!({
                "data": STANDARD.encode(&packed_message),
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[actix_rt::test]
    async fn test_send_message() {
        let node_config = NodeConfig::default();
        let plugin = MockPlugin::new();
        let node = std::sync::Arc::new(std::sync::Mutex::new(
            tap_didcomm_node::DIDCommNode::new(node_config, plugin)
        ));
        let node_data = web::Data::new(node);

        let app = test::init_service(
            App::new()
                .app_data(node_data)
                .service(send_message)
        ).await;

        let message = Message::new("test", json!({"hello": "world"}))
            .unwrap()
            .from("did:example:alice")
            .to(vec!["did:example:bob"]);

        let req = test::TestRequest::post()
            .uri("/didcomm/send")
            .set_json(json!({
                "message": message,
                "packing": PackingType::Signed,
                "endpoint": "http://example.com/didcomm"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[actix_rt::test]
    async fn test_status() {
        let node_config = NodeConfig::default();
        let plugin = MockPlugin::new();
        let node = std::sync::Arc::new(std::sync::Mutex::new(
            tap_didcomm_node::DIDCommNode::new(node_config, plugin)
        ));
        let node_data = web::Data::new(node);

        let app = test::init_service(
            App::new()
                .app_data(node_data)
                .service(status)
        ).await;

        let req = test::TestRequest::post()
            .uri("/status")
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }
} 