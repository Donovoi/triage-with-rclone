use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use rclone_triage::providers::config::ProviderConfig;
use rclone_triage::providers::{discovery, schema};
use rclone_triage::providers::{CloudProvider, ProviderAuthKind, ProviderEntry};
use rclone_triage::rclone::RcloneRunner;
use sha2::{Digest, Sha256};

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
        assert_eq!(entry.backend_name(), provider.rclone_name());
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

// Independent schema contracts, rather than a count of enum variants. Each
// backend must expose the options that its setup route needs. Adding an enum
// variant requires a deliberate contract here (there is no wildcard arm).
// These are checked against the actual pinned executable, not a copied schema.
fn schema_contract(provider: CloudProvider) -> (&'static str, &'static [&'static str]) {
    use CloudProvider::*;
    match provider {
        AzureBlob => ("azureblob", &["account", "key", "sas_url"]),
        AzureFiles => ("azurefiles", &["account", "key", "share_name"]),
        B2 => ("b2", &["account", "key"]),
        Box => ("box", &["token", "root_folder_id"]),
        Cloudinary => ("cloudinary", &["cloud_name", "api_key", "api_secret"]),
        Doi => ("doi", &["doi", "provider"]),
        Drime => ("drime", &["access_token", "root_folder_id"]),
        GoogleDrive => ("drive", &["token", "scope", "root_folder_id"]),
        Dropbox => ("dropbox", &["token", "impersonate"]),
        Fichier => ("fichier", &["api_key", "shared_folder"]),
        FileFabric => ("filefabric", &["url", "permanent_token"]),
        Filelu => ("filelu", &["key"]),
        Filen => ("filen", &["email", "password", "api_key"]),
        FilesCom => ("filescom", &["site", "username", "password", "api_key"]),
        Ftp => ("ftp", &["host", "user", "pass"]),
        Gofile => ("gofile", &["access_token", "root_folder_id"]),
        GoogleCloudStorage => ("gcs", &["service_account_file", "project_number"]),
        GooglePhotos => ("gphotos", &["token", "read_only"]),
        Hdfs => ("hdfs", &["namenode", "username"]),
        HiDrive => ("hidrive", &["token", "scope_access", "scope_role"]),
        Http => ("http", &["url", "headers"]),
        ICloud => ("iclouddrive", &["apple_id", "password", "trust_token"]),
        ImageKit => ("imagekit", &["endpoint", "public_key", "private_key"]),
        InternetArchive => ("internetarchive", &["access_key_id", "secret_access_key"]),
        Internxt => ("internxt", &["email", "pass", "mnemonic"]),
        Jottacloud => ("jottacloud", &["token", "auth_url", "token_url"]),
        Koofr => ("koofr", &["provider", "user", "password"]),
        Linkbox => ("linkbox", &["email", "password", "web_token"]),
        Local => ("local", &["links", "copy_links"]),
        Mailru => ("mailru", &["user", "pass"]),
        Mega => ("mega", &["user", "pass", "2fa"]),
        Memory => ("memory", &["discard"]),
        NetStorage => ("netstorage", &["host", "account", "secret"]),
        OneDrive => (
            "onedrive",
            &["token", "drive_id", "drive_type", "access_scopes"],
        ),
        OpenDrive => ("opendrive", &["username", "password"]),
        OracleObjectStorage => ("oos", &["namespace", "compartment", "config_file"]),
        PCloud => ("pcloud", &["token", "hostname"]),
        PikPak => ("pikpak", &["user", "pass", "device_id"]),
        Pixeldrain => ("pixeldrain", &["api_key", "root_folder_id"]),
        PremiumizeMe => ("premiumizeme", &["token", "api_key"]),
        ProtonDrive => ("protondrive", &["username", "password", "mailbox_password"]),
        Putio => ("putio", &["token", "client_id"]),
        QingStor => ("qingstor", &["access_key_id", "secret_access_key"]),
        Quatrix => ("quatrix", &["api_key", "host"]),
        S3 => ("s3", &["provider", "access_key_id", "secret_access_key"]),
        Seafile => ("seafile", &["url", "user", "pass", "auth_token"]),
        Sftp => ("sftp", &["host", "user", "key_file"]),
        Shade => ("shade", &["drive_id", "api_key"]),
        ShareFile => ("sharefile", &["token", "endpoint"]),
        Sia => ("sia", &["api_url", "api_password"]),
        Smb => ("smb", &["host", "user", "pass", "domain"]),
        Storj => ("storj", &["access_grant", "satellite_address", "api_key"]),
        SugarSync => ("sugarsync", &["refresh_token", "authorization", "user"]),
        Swift => ("swift", &["auth", "user", "key", "tenant"]),
        Ulozto => ("ulozto", &["app_token", "username", "password"]),
        WebDav => ("webdav", &["url", "vendor", "user", "pass"]),
        YandexDisk => ("yandex", &["token", "client_id"]),
        Zoho => ("zoho", &["token", "region", "root_folder_id"]),
    }
}

#[test]
fn every_known_provider_has_an_independent_contract_and_round_trips() {
    let entries = CloudProvider::entries();
    let mut prefixes = HashSet::new();
    for provider in CloudProvider::all() {
        let (prefix, options) = schema_contract(*provider);
        assert!(prefixes.insert(prefix), "duplicated contract for {prefix}");
        assert!(!options.is_empty(), "missing setup contract for {prefix}");
        assert_eq!(CloudProvider::from_str(prefix).unwrap(), *provider);
        assert_eq!(
            CloudProvider::from_str(provider.rclone_name()).unwrap(),
            *provider
        );
        assert_eq!(
            CloudProvider::from_str(provider.rclone_type()).unwrap(),
            *provider
        );
        assert_eq!(
            CloudProvider::from_str(provider.short_name()).unwrap(),
            *provider
        );
        assert_eq!(
            entries
                .iter()
                .filter(|e| e.known == Some(*provider))
                .count(),
            1
        );
        let serialized = serde_json::to_string(provider).unwrap();
        assert_eq!(
            serde_json::from_str::<CloudProvider>(&serialized).unwrap(),
            *provider
        );
    }
}

#[test]
fn discovered_backend_identity_is_independent_of_prefix_and_display_label() {
    let json = r#"[{"Name":"future storage","Prefix":"fsx",
        "Description":"Friendly label","Options":[{"Name":"api_key"}]}]"#;
    let catalog = discovery::providers_from_rclone_json(json).unwrap();
    let entry = &catalog.providers[0];
    assert_eq!(entry.id, "fsx");
    assert_eq!(entry.backend_name(), "future storage");
    assert_eq!(entry.display_name(), "Friendly label");
    assert_eq!(entry.known, None);
    for accepted in ["future storage", "futurestorage", "fsx"] {
        assert!(entry.matches_rclone_type(accepted));
        assert_eq!(
            schema::provider_schema_from_rclone_json(json, accepted)
                .unwrap()
                .unwrap()
                .prefix
                .as_deref(),
            Some("fsx")
        );
    }
    for rejected in ["", "Friendly label", "another backend", "s3"] {
        assert!(!entry.matches_rclone_type(rejected));
    }
    let serialized = serde_json::to_string(entry).unwrap();
    let restored: ProviderEntry = serde_json::from_str(&serialized).unwrap();
    assert_eq!(restored.backend_name(), "future storage");
    assert_eq!(restored.id, "fsx");

    // Entries saved before backend_name was added still use a valid known name.
    let mut legacy =
        serde_json::to_value(ProviderEntry::from_known(CloudProvider::GoogleCloudStorage)).unwrap();
    legacy.as_object_mut().unwrap().remove("backend_name");
    let restored: ProviderEntry = serde_json::from_value(legacy).unwrap();
    assert_eq!(restored.backend_name(), "google cloud storage");
    assert!(restored.matches_rclone_type("gcs"));
}

#[test]
fn backend_specific_auth_is_not_replaced_by_generic_browser_oauth() {
    // Shared OAuth option names do not describe the login protocol. These
    // backends use app passwords, personal tokens, XML authorization, or a
    // tenant-aware callback. Test both static and refreshed provider menus.
    let cases = [
        (CloudProvider::Mailru, ProviderAuthKind::UserPass),
        (CloudProvider::PikPak, ProviderAuthKind::UserPass),
        (CloudProvider::SugarSync, ProviderAuthKind::UserPass),
        (CloudProvider::Jottacloud, ProviderAuthKind::Unknown),
        (CloudProvider::PCloud, ProviderAuthKind::Unknown),
        (CloudProvider::ShareFile, ProviderAuthKind::Unknown),
        (CloudProvider::Zoho, ProviderAuthKind::Unknown),
        (
            CloudProvider::GoogleCloudStorage,
            ProviderAuthKind::KeyBased,
        ),
    ];
    let json = serde_json::to_string(
        &cases
            .iter()
            .map(|(provider, _)| {
                serde_json::json!({"Prefix": provider.rclone_type(), "Options": [
                    {"Name": "client_id"}, {"Name": "token_url"},
                    {"Name": "description", "Help": "OAuth authorization with refresh_token"}
                ]})
            })
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let discovered = discovery::providers_from_rclone_json(&json).unwrap();
    for (provider, expected) in cases {
        let entry = discovered
            .providers
            .iter()
            .find(|entry| entry.known == Some(provider))
            .unwrap();
        assert_eq!(provider.auth_kind(), expected);
        assert_eq!(entry.auth_kind, expected);
        assert!(!entry.oauth_capable);
        assert!(!ProviderEntry::from_known(provider).oauth_capable);
        assert!(!ProviderConfig::for_provider(provider).uses_oauth());
    }
}

#[test]
fn new_backends_remain_available_without_inventing_a_login_protocol() {
    let json = r#"[
        {"Prefix":"new_oauth_storage","Options":[
            {"Name":"client_id"},{"Name":"token"},{"Name":"token_url"}]},
        {"Prefix":"new_key_storage","Options":[
            {"Name":"api_key","Required":true,"IsPassword":true}]}
    ]"#;
    let entries = discovery::providers_from_rclone_json(json).unwrap();
    let schemas = schema::providers_from_rclone_json(json).unwrap();
    assert_eq!(entries.providers.len(), schemas.len());
    for entry in &entries.providers {
        assert_eq!(entry.known, None);
        assert_eq!(entry.auth_kind, ProviderAuthKind::Unknown);
        assert!(!entry.oauth_capable);
        assert!(schema::provider_schema_from_rclone_json(json, &entry.id)
            .unwrap()
            .is_some());
    }
    let key = schema::provider_schema_from_rclone_json(json, "new_key_storage")
        .unwrap()
        .unwrap();
    assert!(key.options[0].required && key.options[0].is_password);
}

#[test]
fn browser_oauth_urls_preserve_callback_state_and_custom_client_exactly() {
    for provider in CloudProvider::all() {
        if provider.auth_kind() != ProviderAuthKind::OAuth {
            continue;
        }
        let config = ProviderConfig::for_provider(*provider);
        let url = config.build_auth_url_with_client_id(
            "client +&=?#雪",
            "http://127.0.0.1:53682/callback?x=1&y=2",
            Some("state +&=?#雪"),
        );
        let (endpoint, query) = url.split_once('?').unwrap();
        assert_eq!(endpoint, config.oauth.auth_url);
        assert!(
            endpoint.starts_with("https://"),
            "insecure endpoint for {provider:?}"
        );
        let mut parameters = HashMap::new();
        for pair in query.split('&') {
            let (key, value) = pair.split_once('=').unwrap();
            assert!(
                parameters.insert(key, value).is_none(),
                "duplicated {key} for {provider:?}"
            );
        }
        assert_eq!(parameters["client_id"], "client%20%2B%26%3D%3F%23%E9%9B%AA");
        assert_eq!(parameters["state"], "state%20%2B%26%3D%3F%23%E9%9B%AA");
        assert_eq!(
            parameters["redirect_uri"],
            "http%3A%2F%2F127.0.0.1%3A53682%2Fcallback%3Fx%3D1%26y%3D2"
        );
        assert_eq!(parameters["response_type"], "code");
        match provider {
            CloudProvider::GoogleDrive | CloudProvider::GooglePhotos => {
                assert_eq!(parameters["access_type"], "offline");
                assert_eq!(parameters["prompt"], "consent");
            }
            CloudProvider::Dropbox => assert_eq!(parameters["token_access_type"], "offline"),
            _ => {}
        }
    }
}

fn release_pin(key: &str) -> &'static str {
    include_str!("../../rclone-version.env")
        .lines()
        .filter_map(|line| line.trim().split_once('='))
        .find_map(|(name, value)| (name == key).then_some(value))
        .unwrap_or_else(|| panic!("Missing {key} in rclone-version.env"))
}

#[test]
#[ignore = "CI runs this explicitly with RCLONE_PROVIDER_SCHEMA_BINARY pointing to a verified native rclone"]
fn pinned_rclone_catalog_matches_provider_contracts() {
    use std::io::Read;
    let binary = PathBuf::from(
        std::env::var_os("RCLONE_PROVIDER_SCHEMA_BINARY")
            .expect("RCLONE_PROVIDER_SCHEMA_BINARY must name the native pinned executable"),
    );
    assert!(
        binary.is_absolute() && binary.is_file(),
        "expected an absolute executable path"
    );
    let hash_key = if cfg!(target_os = "windows") {
        match std::env::consts::ARCH {
            "x86_64" => "RCLONE_EXE_SHA256",
            "x86" => "RCLONE_WINDOWS_X86_EXE_SHA256",
            "aarch64" => "RCLONE_WINDOWS_ARM64_EXE_SHA256",
            _ => panic!("No native executable pin defined for this Windows architecture"),
        }
    } else if cfg!(target_os = "linux") {
        "RCLONE_LINUX_EXE_SHA256"
    } else {
        panic!("No native executable pin defined for this platform")
    };
    let mut hasher = Sha256::new();
    let mut file = std::fs::File::open(&binary).unwrap();
    let mut buffer = [0; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).unwrap();
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    assert_eq!(
        hex::encode(hasher.finalize()),
        release_pin(hash_key),
        "unverified executable; refusing to run it"
    );
    let scratch = tempfile::tempdir().unwrap();
    let config_path = scratch.path().join("empty.conf");
    std::fs::write(&config_path, "").unwrap();
    let runner = RcloneRunner::new(&binary)
        .with_config(&config_path)
        .with_timeout(Duration::from_secs(30));
    let version = runner.run(&["version"]).unwrap();
    assert!(version.success(), "version command failed");
    assert_eq!(
        version.stdout.first().unwrap(),
        &format!("rclone v{}", release_pin("RCLONE_VERSION"))
    );
    // Exercise the same memory-only catalog path used by TUI discovery/schema,
    // even when its caller has an explicit saved config. No global env mutation.
    let output = runner.provider_catalog().unwrap();
    assert!(output.success(), "offline provider catalog command failed");
    let json = output.stdout_string();
    let schemas = schema::providers_from_rclone_json(&json).unwrap();
    let catalog = discovery::providers_from_rclone_json(&json).unwrap();
    assert!(!schemas.is_empty());
    assert_eq!(catalog.stats.excluded_duplicates, 0);
    assert_eq!(catalog.stats.excluded_no_prefix, 0);
    assert_eq!(catalog.stats.total, schemas.len());
    assert_eq!(
        catalog.providers.len() + catalog.stats.excluded_bad,
        schemas.len()
    );

    for provider in CloudProvider::all() {
        let (prefix, required_options) = schema_contract(*provider);
        let entry = catalog
            .providers
            .iter()
            .find(|entry| entry.id == prefix)
            .unwrap_or_else(|| panic!("known provider {provider:?} absent from pinned rclone"));
        assert_eq!(entry.known, Some(*provider));
        assert_eq!(entry.auth_kind, provider.auth_kind());
        let backend = schema::provider_schema_from_rclone_json(&json, prefix)
            .unwrap()
            .unwrap();
        assert_eq!(
            backend.name.as_deref(),
            Some(provider.rclone_name()),
            "canonical name mismatch for {provider:?}"
        );
        assert_eq!(
            backend.prefix.as_deref(),
            Some(provider.rclone_prefix()),
            "option prefix mismatch for {provider:?}"
        );
        assert_eq!(entry.backend_name(), provider.rclone_name());
        let fallback = ProviderEntry::from_known(*provider);
        assert!(fallback.matches_rclone_type(provider.rclone_name()));
        assert!(fallback.matches_rclone_type(prefix));
        let options: HashSet<_> = backend
            .options
            .iter()
            .map(|option| option.name.as_str())
            .collect();
        for required in required_options {
            assert!(
                options.contains(required),
                "{prefix} no longer exposes required option {required}"
            );
        }
        for (option, _) in ProviderConfig::for_provider(*provider).rclone_options {
            assert!(
                options.contains(option),
                "application writes unsupported {prefix} option {option}"
            );
        }
        if entry.oauth_capable {
            for required in ["client_id", "client_secret", "token"] {
                assert!(
                    options.contains(required),
                    "{prefix} lacks OAuth option {required}"
                );
            }
        }
    }
    for entry in &catalog.providers {
        let backend = schema::provider_schema_from_rclone_json(&json, &entry.id)
            .unwrap()
            .unwrap_or_else(|| {
                panic!("discovered backend {} has no manual setup schema", entry.id)
            });
        let canonical_name = backend
            .name
            .as_deref()
            .expect("runtime schema has no canonical Name");
        assert_eq!(entry.backend_name(), canonical_name);
        for accepted in [
            canonical_name.to_string(),
            entry.id.clone(),
            canonical_name.replace(' ', ""),
        ] {
            assert!(
                entry.matches_rclone_type(&accepted),
                "{} does not recognize {accepted}",
                entry.id
            );
            let matched = schema::provider_schema_from_rclone_json(&json, &accepted)
                .unwrap()
                .unwrap();
            assert_eq!(matched.name.as_deref(), Some(canonical_name));
            assert_eq!(matched.prefix.as_deref(), Some(entry.id.as_str()));
        }
        assert!(
            !backend.options.is_empty(),
            "{} has no setup options",
            entry.id
        );
        if entry.known.is_none() {
            assert_eq!(entry.auth_kind, ProviderAuthKind::Unknown);
            assert!(!entry.oauth_capable);
        }
        for option in &backend.options {
            assert!(
                !option.name.trim().is_empty(),
                "{} has an unnamed option",
                entry.id
            );
            // Exercise the conversion used by the manual setup form for every
            // option/example, including booleans, numbers and repeated choices.
            let _ = option.default_string();
            let _ = option.examples_as_strings();
        }
    }
    assert_eq!(
        std::fs::read(&config_path).unwrap(),
        b"",
        "metadata probe changed its config"
    );
    assert_eq!(runner.config_path(), Some(config_path.as_path()));
    let remaining: Vec<_> = std::fs::read_dir(scratch.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(remaining, [std::ffi::OsString::from("empty.conf")]);
    println!("Validated {} backend schemas, {} discoverable entries and {} known-provider contracts; no account login was attempted.",
        schemas.len(), catalog.providers.len(), CloudProvider::all().len());
}
