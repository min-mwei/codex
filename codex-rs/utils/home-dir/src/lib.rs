use dirs::home_dir;
use std::path::PathBuf;

const VORPAL_HOME_ENV_VAR: &str = "VORPAL_HOME";
const LEGACY_CODEX_HOME_ENV_VAR: &str = "CODEX_HOME";

/// Returns the path to the Vorpal configuration directory.
///
/// Resolution order:
/// 1. `VORPAL_HOME`
/// 2. `CODEX_HOME` (legacy fallback)
/// 3. `~/.codex`
///
/// If an env var is set, the value must exist and be a directory. The value is
/// canonicalized and this function returns an error otherwise.
pub fn find_codex_home() -> std::io::Result<PathBuf> {
    let vorpal_home_env = std::env::var(VORPAL_HOME_ENV_VAR).ok();
    let codex_home_env = std::env::var(LEGACY_CODEX_HOME_ENV_VAR).ok();
    resolve_home_from_env(vorpal_home_env.as_deref(), codex_home_env.as_deref())
}

fn resolve_home_from_env(
    vorpal_home_env: Option<&str>,
    codex_home_env: Option<&str>,
) -> std::io::Result<PathBuf> {
    if let Some(val) = vorpal_home_env.filter(|val| !val.is_empty()) {
        return validate_home_from_env(VORPAL_HOME_ENV_VAR, val);
    }

    if let Some(val) = codex_home_env.filter(|val| !val.is_empty()) {
        return validate_home_from_env(LEGACY_CODEX_HOME_ENV_VAR, val);
    }

    default_home_dir()
}

fn validate_home_from_env(env_var_name: &str, val: &str) -> std::io::Result<PathBuf> {
    let path = PathBuf::from(val);
    let metadata = std::fs::metadata(&path).map_err(|err| match err.kind() {
        std::io::ErrorKind::NotFound => std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{env_var_name} points to {val:?}, but that path does not exist"),
        ),
        _ => std::io::Error::new(
            err.kind(),
            format!("failed to read {env_var_name} {val:?}: {err}"),
        ),
    })?;

    if !metadata.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{env_var_name} points to {val:?}, but that path is not a directory"),
        ));
    }

    path.canonicalize().map_err(|err| {
        std::io::Error::new(
            err.kind(),
            format!("failed to canonicalize {env_var_name} {val:?}: {err}"),
        )
    })
}

fn default_home_dir() -> std::io::Result<PathBuf> {
    let mut p = home_dir().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Could not find home directory",
        )
    })?;
    p.push(".codex");
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::resolve_home_from_env;
    use dirs::home_dir;
    use pretty_assertions::assert_eq;
    use std::fs;
    use std::io::ErrorKind;
    use tempfile::TempDir;

    #[test]
    fn vorpal_home_missing_path_is_fatal() {
        let temp_home = TempDir::new().expect("temp home");
        let missing = temp_home.path().join("missing-vorpal-home");
        let missing_str = missing
            .to_str()
            .expect("missing vorpal home path should be valid utf-8");

        let err = resolve_home_from_env(Some(missing_str), None).expect_err("missing VORPAL_HOME");
        assert_eq!(err.kind(), ErrorKind::NotFound);
        assert!(
            err.to_string().contains("VORPAL_HOME"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn vorpal_home_file_path_is_fatal() {
        let temp_home = TempDir::new().expect("temp home");
        let file_path = temp_home.path().join("vorpal-home.txt");
        fs::write(&file_path, "not a directory").expect("write temp file");
        let file_str = file_path
            .to_str()
            .expect("file vorpal home path should be valid utf-8");

        let err = resolve_home_from_env(Some(file_str), None).expect_err("file VORPAL_HOME");
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert!(
            err.to_string().contains("not a directory"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn vorpal_home_valid_directory_canonicalizes() {
        let temp_home = TempDir::new().expect("temp home");
        let temp_str = temp_home
            .path()
            .to_str()
            .expect("temp vorpal home path should be valid utf-8");

        let resolved = resolve_home_from_env(Some(temp_str), None).expect("valid VORPAL_HOME");
        let expected = temp_home
            .path()
            .canonicalize()
            .expect("canonicalize temp home");
        assert_eq!(resolved, expected);
    }

    #[test]
    fn codex_home_is_supported_as_legacy_fallback() {
        let temp_home = TempDir::new().expect("temp home");
        let temp_str = temp_home
            .path()
            .to_str()
            .expect("temp codex home path should be valid utf-8");

        let resolved =
            resolve_home_from_env(None, Some(temp_str)).expect("legacy CODEX_HOME should resolve");
        let expected = temp_home
            .path()
            .canonicalize()
            .expect("canonicalize temp home");
        assert_eq!(resolved, expected);
    }

    #[test]
    fn vorpal_home_takes_precedence_over_codex_home() {
        let vorpal_home = TempDir::new().expect("temp vorpal home");
        let codex_home = TempDir::new().expect("temp codex home");

        let vorpal_home_str = vorpal_home
            .path()
            .to_str()
            .expect("temp vorpal home path should be valid utf-8");
        let codex_home_str = codex_home
            .path()
            .to_str()
            .expect("temp codex home path should be valid utf-8");

        let resolved = resolve_home_from_env(Some(vorpal_home_str), Some(codex_home_str))
            .expect("VORPAL_HOME should win");
        let expected = vorpal_home
            .path()
            .canonicalize()
            .expect("canonicalize vorpal home");
        assert_eq!(resolved, expected);
    }

    #[test]
    fn without_env_uses_default_home_dir() {
        let resolved = resolve_home_from_env(None, None).expect("default home path");
        let mut expected = home_dir().expect("home dir");
        expected.push(".codex");
        assert_eq!(resolved, expected);
    }
}
