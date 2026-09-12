mod constants;
mod parser;

use napi::Result;
use napi_derive::napi;
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;

#[napi]
#[derive(Default)]
pub struct RegPlugin {}

#[napi(object)]
pub struct FileStat {
    pub format: String,
    pub size_bytes: i64,
    pub modified_at: String,
    pub created_at: String,
    pub metadata: HashMap<String, Value>,
}

#[napi]
pub struct RegTools {}

#[napi]
impl RegPlugin {
    #[napi(constructor)]
    pub fn new() -> Self {
        RegPlugin {}
    }

    #[napi(getter)]
    pub fn name(&self) -> String {
        "reg-plugin".to_string()
    }

    #[napi(getter)]
    pub fn description(&self) -> String {
        "File system access to exported Windows registry files (reg).".to_string()
    }

    #[napi]
    pub fn identify(&self, file_path: String) -> bool {
        Path::new(&file_path).extension() == Some("reg".as_ref())
    }

    #[napi(getter)]
    pub fn tools(&self) -> RegTools {
        RegTools {}
    }
}

#[napi]
impl RegTools {
    #[napi]
    pub async fn search(&self, file_path: String, search_term: String) -> Result<Vec<String>> {
        todo!()
    }

    #[napi]
    pub async fn read(
        &self,
        file_path: String,
        offset: i64,
        max_bytes: i64,
    ) -> Result<Vec<String>> {
        todo!()
    }

    #[napi]
    pub async fn stat(&self, file_path: String) -> Result<FileStat> {
        todo!()
    }
}
