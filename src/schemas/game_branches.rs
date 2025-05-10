use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct GameBranches {
    pub game_branches: Vec<GameBranchInfo>,
}

#[derive(Debug, Deserialize)]
pub struct GameBranchInfo {
    pub game: Game,
    pub main: PackageInfo,
    pub pre_download: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct Game {
    pub id: String,
    pub biz: String,
}

#[derive(Debug, Deserialize)]
pub struct PackageInfo {
    pub package_id: String,
    pub branch: String,
    pub password: String,
    pub tag: String,
    pub diff_tags: Vec<String>,
    pub categories: Vec<PackageCategory>,
}

#[derive(Debug, Deserialize)]
pub struct PackageCategory {
    pub category_id: String,
    pub matching_field: String,
}
