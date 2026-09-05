use napi::{Error, Result};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub fn iso8601(time: std::io::Result<SystemTime>) -> String {
    time.ok()
        .map(OffsetDateTime::from)
        .and_then(|time| time.format(&Rfc3339).ok())
        .unwrap_or_default()
}

pub fn unix_epoch_to_iso8601(usec: u64) -> String {
    iso8601(
        UNIX_EPOCH
            .checked_add(Duration::from_micros(usec))
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData)),
    )
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|e| Error::from_reason(format!("worker failed: {e}")))?
}
