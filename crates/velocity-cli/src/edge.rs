use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use velocity_edge::{EdgeApp, EdgeConfig};

pub async fn load_edge_app(config_path: &Path, root: &Path) -> Result<EdgeApp> {
    let source = tokio::fs::read_to_string(config_path)
        .await
        .with_context(|| format!("failed to read edge config {}", config_path.display()))?;
    let config: EdgeConfig = serde_yaml::from_str(&source)
        .with_context(|| format!("edge config {} is not valid YAML", config_path.display()))?;
    EdgeApp::from_config(config, root)
        .map_err(|err| anyhow::anyhow!("failed to build edge runtime: {err}"))
}

pub fn resolve_config_path(base: &Path, config: &Path) -> PathBuf {
    if config.is_absolute() {
        config.to_path_buf()
    } else {
        base.join(config)
    }
}
