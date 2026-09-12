use crate::constants::{REGISTRY_PATH, REGISTRY_VALUE};
use napi::{Error, Result};
use std::fs::File;
use std::io::{BufRead, BufReader};

pub struct Registry {
    pub version: String,
    pub keys: Vec<Key>,
}

pub struct Key {
    pub path: String,
    pub values: Vec<Value>,
}

pub struct Value {
    pub name: Option<String>, // None is the `@` unnamed value
    pub kind: String,
    pub data: String,
}

// Version 5.00 exports are UTF-16LE with a BOM, REGEDIT4 ones ANSI; the BOM picks the strategy.
trait Encoding {
    fn read_line(&self, reader: &mut dyn BufRead) -> Option<String>;
}

struct Ansi;
struct Utf16Le;

impl Encoding for Ansi {
    fn read_line(&self, reader: &mut dyn BufRead) -> Option<String> {
        let mut line = Vec::new();
        match reader.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(String::from_utf8_lossy(&line).into_owned()),
        }
    }
}

impl Encoding for Utf16Le {
    fn read_line(&self, reader: &mut dyn BufRead) -> Option<String> {
        let mut pair = [0u8; 2];
        reader.read_exact(&mut pair).ok()?; // only fails here at end of file
        let mut units = Vec::new();
        while u16::from_le_bytes(pair) != u16::from(b'\n') {
            units.push(u16::from_le_bytes(pair));
            if reader.read_exact(&mut pair).is_err() {
                break;
            }
        }
        Some(String::from_utf16_lossy(&units))
    }
}

struct Lines {
    reader: BufReader<File>,
    encoding: &'static dyn Encoding,
}

impl Lines {
    fn open(filename: &str) -> Result<Self> {
        let mut reader = BufReader::new(
            File::open(filename)
                .map_err(|e| Error::from_reason(format!("Failed to read \"{filename}\": {e}")))?,
        );
        let bom = reader
            .fill_buf()
            .map_err(|e| Error::from_reason(format!("Failed to read \"{filename}\": {e}")))?
            .starts_with(&[0xff, 0xfe]);
        if bom {
            reader.consume(2);
        }

        Ok(Lines {
            reader,
            encoding: if bom { &Utf16Le } else { &Ansi },
        })
    }
}

impl Iterator for Lines {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        let mut line = self
            .encoding
            .read_line(&mut self.reader)?
            .trim_end()
            .to_string();
        // A trailing `\` wraps a long hex list onto the next line.
        while let Some(head) = line.strip_suffix('\\') {
            let Some(rest) = self.encoding.read_line(&mut self.reader) else {
                break;
            };
            line = head.to_string() + rest.trim();
        }
        Some(line)
    }
}

pub fn parse(filename: &str) -> Result<impl Iterator<Item = Key>> {
    let mut lines = Lines::open(filename)?;
    let mut pending = None;

    Ok(std::iter::from_fn(move || {
        let path = pending
            .take()
            .or_else(|| lines.find_map(|line| key_path(&line)))?;
        let mut values = Vec::new();

        for line in lines.by_ref() {
            if let Some(next) = key_path(&line) {
                pending = Some(next);
                break;
            }
            if let Some(value) = REGISTRY_VALUE.captures(&line) {
                values.push(Value {
                    name: value.name("name").map(|name| name.as_str().to_string()),
                    kind: value
                        .name("kind")
                        .map_or_else(String::new, |kind| kind.as_str().to_string()),
                    data: value["data"].to_string(),
                });
            }
        }

        Some(Key { path, values })
    }))
}

fn key_path(line: &str) -> Option<String> {
    REGISTRY_PATH
        .captures(line)
        .map(|caps| caps["path"].to_string())
}
