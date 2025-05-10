use serde::Deserialize;

pub mod game_branches;
pub mod sophon_diff;
pub mod sophon_manifests;

#[derive(Debug, Deserialize)]
pub struct ApiResponse<T> {
    pub retcode: i16,
    pub message: String,
    pub data: T,
}
