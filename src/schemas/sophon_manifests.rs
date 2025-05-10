use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct SophonManifests {
    pub build_id: String,
    pub tag: String,
    pub manifests: Vec<SophonManifest>,
}

#[derive(Debug, Deserialize)]
pub struct SophonManifest {
    pub category_id: String,
    pub category_name: String,
    pub matching_field: String,
    pub manifest: Manifest,
    pub chunk_download: DownloadInfo,
    pub manifest_download: DownloadInfo,
    pub stats: ManifestStats,
    pub deduplicated_stats: ManifestStats,
}

#[derive(Debug, Deserialize)]
pub struct Manifest {
    pub id: String,
    pub checksum: String,
    pub compressed_size: String,
    pub uncompressed_size: String,
}

#[derive(Debug, Deserialize)]
pub struct DownloadInfo {
    pub encryption: u8,
    pub password: String,
    pub compression: u8,
    pub url_prefix: String,
    pub url_suffix: String,
}

#[derive(Debug, Deserialize)]
pub struct ManifestStats {
    pub compressed_size: String,
    pub uncompressed_size: String,
    pub file_count: String,
    pub chunk_count: String,
}
