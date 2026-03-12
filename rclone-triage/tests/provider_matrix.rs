use std::collections::HashSet;

use rclone_triage::providers::config::ProviderConfig;
use rclone_triage::providers::{CloudProvider, ProviderAuthKind, ProviderEntry};

#[test]
fn test_all_providers_have_unique_ids_and_names() {
    let mut rclone_types = HashSet::new();
    let mut short_names = HashSet::new();
    let mut display_names = HashSet::new();

    for provider in CloudProvider::all() {
        assert!(
            !provider.rclone_type().is_empty(),
            "{} is missing an rclone type",
            provider.display_name()
        );
        assert!(
            !provider.short_name().is_empty(),
            "{} is missing a short name",
            provider.display_name()
        );
        assert!(
            !provider.display_name().is_empty(),
            "provider {:?} is missing a display name",
            provider
        );
        assert!(
            provider.rclone_type().chars().all(|ch| !ch.is_whitespace()),
            "{} rclone type should not contain whitespace",
            provider.display_name()
        );
        assert!(
            provider.short_name().chars().all(|ch| !ch.is_whitespace()),
            "{} short name should not contain whitespace",
            provider.display_name()
        );
        assert_eq!(
            provider.rclone_type(),
            provider.rclone_type().to_ascii_lowercase(),
            "{} rclone type should be lowercase",
            provider.display_name()
        );
        assert_eq!(
            provider.short_name(),
            provider.short_name().to_ascii_lowercase(),
            "{} short name should be lowercase",
            provider.display_name()
        );

        assert!(
            rclone_types.insert(provider.rclone_type()),
            "duplicate rclone type: {}",
            provider.rclone_type()
        );
        assert!(
            short_names.insert(provider.short_name()),
            "duplicate short name: {}",
            provider.short_name()
        );
        assert!(
            display_names.insert(provider.display_name()),
            "duplicate display name: {}",
            provider.display_name()
        );

        let entry = ProviderEntry::from_known(*provider);
        assert_eq!(entry.id, provider.rclone_type());
        assert_eq!(entry.name, provider.display_name());
        assert_eq!(entry.known, Some(*provider));
        assert_eq!(entry.auth_kind(), provider.auth_kind());
        assert_eq!(
            entry.oauth_capable,
            provider.auth_kind() == ProviderAuthKind::OAuth,
            "{} oauth flag should match auth kind",
            provider.display_name()
        );
    }
}

#[test]
fn test_oauth_provider_config_is_complete() {
    for provider in CloudProvider::all() {
        let config = ProviderConfig::for_provider(*provider);

        match provider.auth_kind() {
            ProviderAuthKind::OAuth => {
                assert!(
                    config.uses_oauth(),
                    "{} should have OAuth config",
                    provider.display_name()
                );
                assert!(
                    !config.oauth.client_id.trim().is_empty(),
                    "{} should define a client id",
                    provider.display_name()
                );
                assert!(
                    !config.oauth.auth_url.trim().is_empty(),
                    "{} should define an auth URL",
                    provider.display_name()
                );
                assert!(
                    !config.oauth.token_url.trim().is_empty(),
                    "{} should define a token URL",
                    provider.display_name()
                );

                let auth_url =
                    config.build_auth_url("http://127.0.0.1:53682/", Some("provider-matrix-state"));
                assert!(
                    auth_url.contains("client_id="),
                    "{} auth URL should include client_id",
                    provider.display_name()
                );
                assert!(
                    auth_url.contains("redirect_uri="),
                    "{} auth URL should include redirect_uri",
                    provider.display_name()
                );
                assert!(
                    auth_url.contains("response_type=code"),
                    "{} auth URL should request an OAuth code",
                    provider.display_name()
                );
                assert!(
                    auth_url.contains("provider-matrix-state"),
                    "{} auth URL should preserve state",
                    provider.display_name()
                );
            }
            ProviderAuthKind::KeyBased | ProviderAuthKind::UserPass | ProviderAuthKind::Unknown => {
                assert!(
                    !config.uses_oauth(),
                    "{} should not advertise OAuth config",
                    provider.display_name()
                );
            }
        }
    }
}

#[test]
fn test_hash_types_are_normalized_and_unique_per_provider() {
    for provider in CloudProvider::all() {
        let mut seen = HashSet::new();
        for hash_type in provider.hash_types() {
            assert_eq!(
                *hash_type,
                hash_type.to_ascii_lowercase(),
                "{} hash types should be lowercase",
                provider.display_name()
            );
            assert!(
                seen.insert(*hash_type),
                "{} should not repeat hash type '{}'",
                provider.display_name(),
                hash_type
            );
        }
    }
}

#[test]
fn test_major_provider_families_have_expected_auth_kinds() {
    for provider in [
        CloudProvider::GoogleDrive,
        CloudProvider::OneDrive,
        CloudProvider::Dropbox,
        CloudProvider::Box,
        CloudProvider::GooglePhotos,
    ] {
        assert_eq!(provider.auth_kind(), ProviderAuthKind::OAuth);
    }

    for provider in [
        CloudProvider::S3,
        CloudProvider::AzureBlob,
        CloudProvider::AzureFiles,
        CloudProvider::B2,
        CloudProvider::GoogleCloudStorage,
    ] {
        assert_eq!(provider.auth_kind(), ProviderAuthKind::KeyBased);
    }

    for provider in [
        CloudProvider::Ftp,
        CloudProvider::Sftp,
        CloudProvider::WebDav,
        CloudProvider::Smb,
        CloudProvider::ICloud,
    ] {
        assert_eq!(provider.auth_kind(), ProviderAuthKind::UserPass);
    }
}
