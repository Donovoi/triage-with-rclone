use anyhow::Result;

use crate::ui::App;

pub(crate) fn resolve_provider_remotes(
    config: &crate::rclone::RcloneConfig,
    provider: &crate::providers::ProviderEntry,
) -> Result<Vec<String>> {
    let parsed = config.parse()?;
    let remotes = parsed
        .remotes_by_type(provider.short_name())
        .into_iter()
        .map(|remote| remote.name.clone())
        .collect();
    Ok(remotes)
}

pub(crate) fn choose_remote_or_prompt(
    app: &mut App,
    provider: &crate::providers::ProviderEntry,
    remotes: Vec<String>,
) -> Result<Option<String>> {
    if let Some(current) = app.remote.chosen.clone() {
        if remotes.iter().any(|remote| remote == &current) {
            return Ok(Some(current));
        }
        app.remote.chosen = None;
    }

    if remotes.len() == 1 {
        let remote_name = remotes[0].clone();
        app.remote.chosen = Some(remote_name.clone());
        return Ok(Some(remote_name));
    }

    if remotes.is_empty() {
        return Ok(None);
    }

    app.remote.options = remotes;
    app.remote.selected = app
        .remote.chosen
        .as_ref()
        .and_then(|remote| app.remote.options.iter().position(|r| r == remote))
        .unwrap_or(0);
    app.provider.status = format!(
        "Multiple remotes found for {}. Select one to continue.",
        provider.display_name()
    );
    app.state = crate::ui::AppState::RemoteSelect;
    Ok(None)
}

