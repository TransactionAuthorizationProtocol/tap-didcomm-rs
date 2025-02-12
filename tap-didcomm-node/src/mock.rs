use async_trait::async_trait;
use tap_didcomm_core::{
    plugin::DIDCommPlugin,
    error::Result,
    Message,
};

pub struct MockPlugin;

impl MockPlugin {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl DIDCommPlugin for MockPlugin {
    async fn handle_message(&self, message: Message) -> Result<()> {
        tracing::debug!("Mock plugin handling message: {:?}", message);
        Ok(())
    }
} 