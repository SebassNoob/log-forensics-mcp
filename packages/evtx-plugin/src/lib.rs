// Skeleton: every method body is `todo!()`, so parameters are not yet read.
// Delete this once the implementations land.
#![allow(unused_variables)]

use napi::bindgen_prelude::Result;
use napi_derive::napi;
use std::collections::HashMap;

/// Search strategy for Windows Event Log files.
#[napi]
pub struct EvtxPlugin {}

#[napi]
impl EvtxPlugin {
  #[napi(constructor)]
  pub fn new() -> Self {
    EvtxPlugin {}
  }

  #[napi(getter)]
  pub fn name(&self) -> String {
    todo!()
  }

  #[napi(getter)]
  pub fn description(&self) -> String {
    todo!()
  }

  /// Whether this plugin handles `file_path`. Detection is by path alone.
  #[napi]
  pub fn identify(&self, file_path: String) -> bool {
    todo!()
  }

  #[napi(getter)]
  pub fn tools(&self) -> EvtxTools {
    EvtxTools {}
  }
}

/// The tools this plugin exposes. Each is optional on the TypeScript side, so
/// an unsupported tool should return an error rather than a fabricated result.
#[napi]
pub struct EvtxTools {}

#[napi]
impl EvtxTools {
  #[napi]
  pub async fn search(&self, file_path: String, search_term: String) -> Result<Vec<String>> {
    todo!()
  }

  #[napi]
  pub async fn read(&self, file_path: String, offset: i64, max_bytes: i64) -> Result<Vec<String>> {
    todo!()
  }

  #[napi]
  pub async fn stat(&self, file_path: String) -> Result<HashMap<String, serde_json::Value>> {
    todo!()
  }
}
