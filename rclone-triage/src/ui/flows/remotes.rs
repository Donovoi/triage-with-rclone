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
    app.remote.checked = vec![false; app.remote.options.len()];
    app.remote.selected = app
        .remote
        .chosen
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

/// Resolve all remotes from a config regardless of type.
pub(crate) fn resolve_all_remotes(
    config: &crate::rclone::RcloneConfig,
) -> Result<Vec<(String, String)>> {
    let parsed = config.parse()?;
    let remotes = parsed
        .remotes
        .iter()
        .map(|r| (r.name.clone(), r.remote_type.clone()))
        .collect();
    Ok(remotes)
}

/// Choose a remote from all available remotes (no provider filter).
/// Returns the remote name and type if selected, or None if going to RemoteSelect.
pub(crate) fn choose_remote_from_all(
    app: &mut App,
    remotes: Vec<(String, String)>,
) -> Result<Option<(String, String)>> {
    if let Some(current) = app.remote.chosen.clone() {
        if let Some(r) = remotes.iter().find(|(name, _)| name == &current) {
            return Ok(Some(r.clone()));
        }
        app.remote.chosen = None;
    }

    if remotes.len() == 1 {
        let (name, rtype) = remotes[0].clone();
        app.remote.chosen = Some(name.clone());
        return Ok(Some((name, rtype)));
    }

    if remotes.is_empty() {
        return Ok(None);
    }

    // Show remotes with their type for user clarity
    app.remote.options = remotes
        .iter()
        .map(|(name, rtype)| format!("{} ({})", name, rtype))
        .collect();
    app.remote.checked = vec![false; app.remote.options.len()];
    app.remote.selected = 0;
    app.provider.status =
        "Multiple remotes found. Select one or more to continue (Space to toggle).".to_string();
    app.state = crate::ui::AppState::RemoteSelect;
    Ok(None)
}
