# tap-didcomm-web

Web server implementation of the DIDComm protocol for the TAP (Trust Anchor Protocol) system.

## Overview

`tap-didcomm-web` provides a web server interface for DIDComm operations, built on top of the Warp framework. It offers:
- RESTful API endpoints for DIDComm messaging
- OpenAPI/Swagger documentation
- CORS support
- Error handling and logging

## Features

- **RESTful API**:
  - `GET /status` - Server health check
  - `POST /receive` - Receive and decrypt DIDComm messages
  - OpenAPI documentation at `/api-doc.json`
  - Swagger UI at `/swagger-ui`
- **Warp Framework**:
  - Async request handling
  - Type-safe routing
  - Built-in CORS support
- **Documentation**:
  - Interactive Swagger UI
  - OpenAPI 3.0 specifications
  - Detailed API documentation
- **Error Handling**:
  - Structured error responses
  - Proper HTTP status codes
  - Detailed error messages

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
tap-didcomm-web = { path = "../tap-didcomm-web" }
```

Basic example:

```rust
use tap_didcomm_web::{UniversalPlugin, ServerConfig};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize the plugin
    let plugin = UniversalPlugin::new()?;
    
    // Start the server
    let config = ServerConfig {
        host: "127.0.0.1".to_string(),
        port: 8000,
        cors: CorsConfig::default(),
    };
    
    let server = DIDCommServer::new(config, plugin);
    server.run().await?;
    
    Ok(())
}
```

## API Documentation

### Status Endpoint

```http
GET /status
```

Response:
```json
{
  "status": "ok"
}
```

### Receive Message Endpoint

```http
POST /receive
Content-Type: application/json

{
  "message": {
    "content": "encrypted message"
  }
}
```

Response:
```json
{
  "message": {
    "decrypted": "content"
  }
}
```

## Configuration

The server can be configured through `ServerConfig`:

```rust
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub cors: CorsConfig,
}

pub struct CorsConfig {
    pub allowed_origins: Vec<String>,
    pub allow_credentials: bool,
}
```

## Testing

Run the test suite:

```bash
cargo test
```

For integration tests with a running server:

```bash
cargo test --test '*'
```

## OpenAPI Documentation

The API is documented using OpenAPI 3.0 specifications. You can access:
- Raw OpenAPI JSON at `http://localhost:8000/api-doc.json`
- Interactive Swagger UI at `http://localhost:8000/swagger-ui`

## Error Handling

Errors are returned as JSON responses with appropriate HTTP status codes:

```json
{
  "error": "Invalid message format",
  "status": 400
}
```

## Security

This crate handles sensitive DIDComm messages. See the [SECURITY.md](../SECURITY.md) file for security considerations and reporting vulnerabilities.

## License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.

## Contributing

Please read [CONTRIBUTING.md](../CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/your/project/tags). 