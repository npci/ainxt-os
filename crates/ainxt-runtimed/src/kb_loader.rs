// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! File-system corpus loader for the live knowledge base.
//!
//! Populates `[kb.documents]` from a directory of `.jsonl`, `.md`, or `.txt` files at daemon startup.
//! Inline `[[kb.documents]]` entries take precedence over file-loaded docs by id.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ainxt_types::DataClass;
use serde::Deserialize;

use crate::{KbDocument, KbLoaderConfig, KbScope};

#[derive(Debug, thiserror::Error)]
pub enum KbLoadError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json in {path}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("frontmatter in {path}: {source}")]
    Frontmatter {
        path: PathBuf,
        source: toml::de::Error,
    },
}

/// Load documents from the configured directory and append/merge them into `out`.
pub fn load_from_dir(cfg: &KbLoaderConfig, out: &mut Vec<KbDocument>) -> Result<(), KbLoadError> {
    let dir = match &cfg.dir {
        Some(d) if !d.is_empty() => PathBuf::from(d),
        _ => return Ok(()),
    };
    let globs = if cfg.globs.is_empty() {
        vec![
            "*.jsonl".to_string(),
            "*.md".to_string(),
            "*.txt".to_string(),
        ]
    } else {
        cfg.globs.clone()
    };

    let mut seen: BTreeMap<String, usize> = out
        .iter()
        .enumerate()
        .map(|(i, d)| (d.id.clone(), i))
        .collect();

    for g in &globs {
        for entry in glob::glob(dir.join(g).to_str().unwrap_or(g)).map_err(|e| {
            KbLoadError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        })? {
            let path = entry.map_err(|e| KbLoadError::Io(e.into()))?;
            let docs = load_file(&path, cfg.default_class)?;
            for d in docs {
                if let Some(_idx) = seen.get(&d.id) {
                    // Inline config entries override file-loaded docs by id.
                    continue;
                }
                seen.insert(d.id.clone(), out.len());
                out.push(d);
            }
        }
    }
    Ok(())
}

fn load_file(path: &Path, default_class: DataClass) -> Result<Vec<KbDocument>, KbLoadError> {
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
    match ext {
        "jsonl" => load_jsonl(path, default_class),
        "md" | "txt" => load_text(path, default_class),
        _ => Ok(Vec::new()),
    }
}

fn load_jsonl(path: &Path, _default_class: DataClass) -> Result<Vec<KbDocument>, KbLoadError> {
    let text = std::fs::read_to_string(path)?;
    let mut docs = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let chunk: ainxt_context::Chunk =
            serde_json::from_str(line).map_err(|e| KbLoadError::Json {
                path: path.to_path_buf(),
                source: e,
            })?;
        docs.push(KbDocument {
            id: chunk.id,
            source: chunk.source,
            text: chunk.text,
            data_class: chunk.data_class,
            scope: KbScope::Platform,
            namespace: None,
            repo: None,
            department: chunk.acl.as_ref().and_then(|a| {
                a.departments
                    .as_ref()
                    .and_then(|d| d.iter().next().cloned())
            }),
            max_ad_level: chunk.acl.as_ref().and_then(|a| a.max_ad_level),
            allow_groups: chunk
                .acl
                .as_ref()
                .map(|a| a.allow_groups.iter().cloned().collect())
                .unwrap_or_default(),
            deny_groups: chunk
                .acl
                .as_ref()
                .map(|a| a.deny_groups.iter().cloned().collect())
                .unwrap_or_default(),
            row_attributes: chunk.attributes,
        });
    }
    Ok(docs)
}

fn load_text(path: &Path, default_class: DataClass) -> Result<Vec<KbDocument>, KbLoadError> {
    let raw = std::fs::read_to_string(path)?;
    let (front, body) = split_frontmatter(&raw);
    let meta: TextMeta = if front.is_empty() {
        TextMeta::default()
    } else {
        toml::from_str(front).map_err(|e| KbLoadError::Frontmatter {
            path: path.to_path_buf(),
            source: e,
        })?
    };
    let source = meta.source.unwrap_or_else(|| {
        path.file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string())
    });
    Ok(vec![KbDocument {
        id: meta.id.unwrap_or_else(|| source.clone()),
        source,
        text: body.trim().to_string(),
        data_class: meta.data_class.unwrap_or(default_class),
        scope: meta.scope.unwrap_or(KbScope::Platform),
        namespace: meta.namespace,
        repo: meta.repo,
        department: meta.department,
        max_ad_level: meta.max_ad_level,
        allow_groups: meta.allow_groups,
        deny_groups: meta.deny_groups,
        row_attributes: meta.row_attributes,
    }])
}

#[derive(Debug, Default, Deserialize)]
struct TextMeta {
    id: Option<String>,
    source: Option<String>,
    #[serde(default)]
    data_class: Option<DataClass>,
    #[serde(default)]
    scope: Option<KbScope>,
    namespace: Option<String>,
    repo: Option<String>,
    department: Option<String>,
    max_ad_level: Option<u8>,
    #[serde(default)]
    allow_groups: Vec<String>,
    #[serde(default)]
    deny_groups: Vec<String>,
    #[serde(default)]
    row_attributes: BTreeMap<String, String>,
}

fn split_frontmatter(s: &str) -> (&str, &str) {
    if s.starts_with("---") {
        if let Some(end) = s[3..].find("\n---") {
            let end = end + 3;
            return (&s[3..end], &s[end + 4..]);
        }
    }
    ("", s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ainxt_types::DataClass;

    #[test]
    fn loads_jsonl_and_text_into_kb_documents() {
        let dir = std::env::temp_dir().join(format!("ainxt-kb-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        std::fs::write(
            dir.join("docs.jsonl"),
            r#"{"id":"c1","source":"a.md","text":"hello","data_class":"public"}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("b.md"),
            "---\nid = \"c2\"\ndata_class = \"internal\"\n---\nworld",
        )
        .unwrap();

        let cfg = KbLoaderConfig {
            dir: Some(dir.to_string_lossy().to_string()),
            ..Default::default()
        };
        let mut docs = Vec::new();
        load_from_dir(&cfg, &mut docs).unwrap();

        assert_eq!(docs.len(), 2);
        assert_eq!(docs[0].id, "c1");
        assert_eq!(docs[1].id, "c2");
        assert_eq!(docs[1].data_class, DataClass::Internal);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn inline_entries_override_file_by_id() {
        let dir = std::env::temp_dir().join(format!("ainxt-kb-override-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        std::fs::write(
            dir.join("docs.jsonl"),
            r#"{"id":"c1","source":"a.md","text":"hello","data_class":"public"}"#,
        )
        .unwrap();

        let cfg = KbLoaderConfig {
            dir: Some(dir.to_string_lossy().to_string()),
            ..Default::default()
        };
        let mut docs = vec![KbDocument {
            id: "c1".to_string(),
            source: "inline".to_string(),
            text: "override".to_string(),
            data_class: DataClass::Confidential,
            scope: KbScope::Platform,
            namespace: None,
            repo: None,
            department: None,
            max_ad_level: None,
            allow_groups: Vec::new(),
            deny_groups: Vec::new(),
            row_attributes: BTreeMap::new(),
        }];
        load_from_dir(&cfg, &mut docs).unwrap();

        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0].text, "override");
        assert_eq!(docs[0].data_class, DataClass::Confidential);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
