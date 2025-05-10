use std::collections::HashMap;

use serde::Deserialize;

use super::sophon_manifests::{DownloadInfo, Manifest, ManifestStats};

#[derive(Debug, Deserialize)]
pub struct SophonDiffs {
    pub build_id: String,
    pub patch_id: String,
    pub tag: String,
    pub manifests: Vec<SophonDiff>,
}

#[derive(Debug, Deserialize)]
pub struct SophonDiff {
    pub category_id: String,
    pub category_name: String,
    pub matching_field: String,
    pub manifest: Manifest,
    pub diff_download: DownloadInfo,
    pub manifest_download: DownloadInfo,
    pub stats: HashMap<String, ManifestStats>,
}
