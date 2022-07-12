use anyhow::{Error, Result};
use async_trait::async_trait;
use sxg_rs::storage::Storage;

pub struct FastlyStorage {
    store: fastly::ConfigStore,
}

impl FastlyStorage {
    pub fn new(name: &str) -> Self {
        let store = fastly::ConfigStore::open(name);
        FastlyStorage { store }
    }
}

#[cfg_attr(feature = "wasm", async_trait(?Send))]
#[cfg_attr(not(feature = "wasm"), async_trait)]
impl Storage for FastlyStorage {
    async fn read(&self, k: &str) -> Result<Option<String>> {
        Ok(self.store.get(k))
    }
    async fn write(&self, _k: &str, _v: &str) -> Result<()> {
        Err(Error::msg(
            "Writing to edge dictionary is not allowed by worker.",
        ))
    }
}
