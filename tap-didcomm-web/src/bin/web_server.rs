use async_trait::async_trait;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::json;
use ssi_jwk::JWK;
use std::sync::Arc;
use tap_didcomm_core::{
    error::Result,
    plugin::{DIDCommPlugin, DIDResolver, Encryptor, Signer},
    types::{Message, PackingType},
};
use tap_didcomm_node::DIDCommNode;
use utoipa::OpenApi;
use utoipa::ToSchema;
use utoipa_swagger_ui::SwaggerUi;
use warp::{Filter, Rejection, Reply};

/// Status response model
#[derive(Serialize, Deserialize, ToSchema)]
struct StatusResponse {
    status: String,
}

/// DIDComm message model
#[derive(Serialize, Deserialize, ToSchema)]
struct DIDCommMessage {
    #[schema(example = "json({\"content\": \"encrypted message\"})")]
    message: serde_json::Value,
}

#[derive(OpenApi)]
#[openapi(
    paths(
        status,
        receive_message
    ),
    components(
        schemas(StatusResponse, DIDCommMessage)
    ),
    tags(
        (name = "didcomm", description = "DIDComm message endpoints")
    )
)]
struct ApiDoc;

/// A universal plugin that implements all required DIDComm traits
pub struct UniversalPlugin {
    mock_plugin: Arc<Box<dyn DIDCommPlugin + Send + Sync>>,
}

impl UniversalPlugin {
    pub fn new() -> Result<Self> {
        // For testing, use a mock plugin
        let mock_plugin = Arc::new(Box::new(tap_didcomm_core::tests::MockTestPlugin));
        Ok(Self { mock_plugin })
    }
}

#[async_trait::async_trait]
impl DIDResolver for UniversalPlugin {
    async fn resolve(&self, did: &str) -> Result<String> {
        self.mock_plugin.resolver().resolve(did).await
    }
}

#[async_trait::async_trait]
impl Signer for UniversalPlugin {
    async fn sign(&self, message: &[u8], from: &str) -> Result<Vec<u8>> {
        self.mock_plugin.signer().sign(message, from).await
    }

    async fn verify(&self, message: &[u8], signature: &[u8], from: &str) -> Result<bool> {
        self.mock_plugin
            .signer()
            .verify(message, signature, from)
            .await
    }
}

#[async_trait::async_trait]
impl Encryptor for UniversalPlugin {
    async fn encrypt(&self, message: &[u8], to: &[&str], from: Option<&str>) -> Result<Vec<u8>> {
        self.mock_plugin
            .encryptor()
            .encrypt(message, to, from)
            .await
    }

    async fn decrypt(&self, message: &[u8], recipient: &str) -> Result<Vec<u8>> {
        self.mock_plugin
            .encryptor()
            .decrypt(message, recipient)
            .await
    }
}

impl DIDCommPlugin for UniversalPlugin {
    fn resolver(&self) -> &dyn DIDResolver {
        self
    }

    fn signer(&self) -> &dyn Signer {
        self
    }

    fn encryptor(&self) -> &dyn Encryptor {
        self
    }
}

/// Error type for web server operations
#[derive(Debug)]
struct WebError(String);

impl warp::reject::Reject for WebError {}

impl From<tap_didcomm_core::error::Error> for WebError {
    fn from(err: tap_didcomm_core::error::Error) -> Self {
        WebError(err.to_string())
    }
}

/// Handle rejections (errors) from filters
async fn handle_rejection(err: Rejection) -> Result<impl Reply, Rejection> {
    if let Some(WebError(message)) = err.find() {
        Ok(warp::reply::with_status(
            message.clone(),
            warp::http::StatusCode::BAD_REQUEST,
        ))
    } else {
        Ok(warp::reply::with_status(
            "Internal Server Error".to_string(),
            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
        ))
    }
}

/// Get server status
#[utoipa::path(
    get,
    path = "/status",
    tag = "didcomm",
    responses(
        (status = 200, description = "Server status retrieved successfully", body = StatusResponse)
    )
)]
async fn status() -> impl Reply {
    warp::reply::json(&StatusResponse {
        status: "ok".to_string(),
    })
}

/// Receive and decrypt a DIDComm message
#[utoipa::path(
    post,
    path = "/receive",
    tag = "didcomm",
    request_body = DIDCommMessage,
    responses(
        (status = 200, description = "Message received and decrypted successfully", body = DIDCommMessage),
        (status = 400, description = "Invalid message format or decryption failed")
    )
)]
async fn receive_message(
    message: DIDCommMessage,
    plugin: Arc<UniversalPlugin>,
) -> Result<impl Reply, Rejection> {
    let message_bytes = serde_json::to_vec(&message.message)
        .map_err(|e| warp::reject::custom(WebError(e.to_string())))?;
    let decrypted = plugin
        .decrypt(&message_bytes, "did:example:recipient")
        .await
        .map_err(|e| warp::reject::custom(WebError(e.to_string())))?;
    Ok(warp::reply::json(&serde_json::from_slice::<
        serde_json::Value,
    >(&decrypted)?))
}

#[tokio::main]
async fn main() -> Result<()> {
    let plugin = Arc::new(UniversalPlugin::new()?);
    let plugin = warp::any().map(move || plugin.clone());

    // OpenAPI documentation
    let api_doc = warp::path("api-doc.json")
        .and(warp::get())
        .map(|| warp::reply::json(&ApiDoc::openapi()));

    // Status endpoint
    let status = warp::path("status").and(warp::get()).and_then(status);

    // Receive endpoint
    let receive = warp::path("receive")
        .and(warp::post())
        .and(warp::body::json())
        .and(plugin.clone())
        .and_then(receive_message);

    // Swagger UI
    let swagger_ui = SwaggerUi::new("/swagger-ui").url("/api-doc.json", ApiDoc::openapi());

    // Combine routes
    let routes = status
        .or(receive)
        .or(api_doc)
        .or(swagger_ui)
        .recover(handle_rejection)
        .with(warp::cors().allow_any_origin());

    println!("Server running on http://127.0.0.1:8000");
    println!("API documentation available at http://127.0.0.1:8000/swagger-ui");
    warp::serve(routes).run(([127, 0, 0, 1], 8000)).await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use warp::test::request;

    #[tokio::test]
    async fn test_server_endpoints() -> Result<()> {
        let plugin = Arc::new(UniversalPlugin::new()?);
        let plugin = warp::any().map(move || plugin.clone());

        // Test status endpoint
        let status = warp::path("status").and(warp::get()).and_then(status);

        let res = request().method("GET").path("/status").reply(&status).await;

        assert_eq!(res.status(), 200);
        assert_eq!(res.body(), r#"{"status":"ok"}"#.as_bytes());

        // Test receive endpoint
        let receive = warp::path("receive")
            .and(warp::post())
            .and(warp::body::json())
            .and(plugin.clone())
            .and_then(receive_message);

        let res = request()
            .method("POST")
            .path("/receive")
            .json(&DIDCommMessage {
                message: json!({"test": "message"}),
            })
            .reply(&receive)
            .await;

        assert_eq!(res.status(), 200);

        Ok(())
    }
}
