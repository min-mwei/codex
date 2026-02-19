use chrono::DateTime;
use chrono::Utc;
use codex_api::AuthProvider as ApiAuthProvider;
use codex_api::TransportError;
use codex_api::error::ApiError;
use codex_api::rate_limits::parse_promo_message;
use codex_api::rate_limits::parse_rate_limit_for_limit;
use http::HeaderMap;
use serde::Deserialize;

use crate::auth::CodexAuth;
use crate::error::CodexErr;
use crate::error::RetryLimitReachedError;
use crate::error::UnexpectedResponseError;
use crate::error::UsageLimitReachedError;
use crate::model_provider_info::ModelProviderInfo;
use crate::token_data::PlanType;
use tokio::process::Command;

const AZURE_OPENAI_ENTRA_TOKEN_ENV_VAR: &str = "AZURE_OPENAI_ENTRA_TOKEN";

pub(crate) fn map_api_error(err: ApiError) -> CodexErr {
    match err {
        ApiError::ContextWindowExceeded => CodexErr::ContextWindowExceeded,
        ApiError::QuotaExceeded => CodexErr::QuotaExceeded,
        ApiError::UsageNotIncluded => CodexErr::UsageNotIncluded,
        ApiError::Retryable { message, delay } => CodexErr::Stream(message, delay),
        ApiError::Stream(msg) => CodexErr::Stream(msg, None),
        ApiError::ServerOverloaded => CodexErr::ServerOverloaded,
        ApiError::Api { status, message } => CodexErr::UnexpectedStatus(UnexpectedResponseError {
            status,
            body: message,
            url: None,
            cf_ray: None,
            request_id: None,
        }),
        ApiError::InvalidRequest { message } => CodexErr::InvalidRequest(message),
        ApiError::Transport(transport) => match transport {
            TransportError::Http {
                status,
                url,
                headers,
                body,
            } => {
                let body_text = body.unwrap_or_default();

                if status == http::StatusCode::SERVICE_UNAVAILABLE
                    && let Ok(value) = serde_json::from_str::<serde_json::Value>(&body_text)
                    && matches!(
                        value
                            .get("error")
                            .and_then(|error| error.get("code"))
                            .and_then(serde_json::Value::as_str),
                        Some("server_is_overloaded" | "slow_down")
                    )
                {
                    return CodexErr::ServerOverloaded;
                }

                if status == http::StatusCode::BAD_REQUEST {
                    if body_text
                        .contains("The image data you provided does not represent a valid image")
                    {
                        CodexErr::InvalidImageRequest()
                    } else {
                        CodexErr::InvalidRequest(body_text)
                    }
                } else if status == http::StatusCode::INTERNAL_SERVER_ERROR {
                    CodexErr::InternalServerError
                } else if status == http::StatusCode::TOO_MANY_REQUESTS {
                    if let Ok(err) = serde_json::from_str::<UsageErrorResponse>(&body_text) {
                        if err.error.error_type.as_deref() == Some("usage_limit_reached") {
                            let limit_id = extract_header(headers.as_ref(), ACTIVE_LIMIT_HEADER);
                            let rate_limits = headers.as_ref().and_then(|map| {
                                parse_rate_limit_for_limit(map, limit_id.as_deref())
                            });
                            let promo_message = headers.as_ref().and_then(parse_promo_message);
                            let resets_at = err
                                .error
                                .resets_at
                                .and_then(|seconds| DateTime::<Utc>::from_timestamp(seconds, 0));
                            return CodexErr::UsageLimitReached(UsageLimitReachedError {
                                plan_type: err.error.plan_type,
                                resets_at,
                                rate_limits: rate_limits.map(Box::new),
                                promo_message,
                            });
                        } else if err.error.error_type.as_deref() == Some("usage_not_included") {
                            return CodexErr::UsageNotIncluded;
                        }
                    }

                    CodexErr::RetryLimit(RetryLimitReachedError {
                        status,
                        request_id: extract_request_tracking_id(headers.as_ref()),
                    })
                } else {
                    CodexErr::UnexpectedStatus(UnexpectedResponseError {
                        status,
                        body: body_text,
                        url,
                        cf_ray: extract_header(headers.as_ref(), CF_RAY_HEADER),
                        request_id: extract_request_id(headers.as_ref()),
                    })
                }
            }
            TransportError::RetryLimit => CodexErr::RetryLimit(RetryLimitReachedError {
                status: http::StatusCode::INTERNAL_SERVER_ERROR,
                request_id: None,
            }),
            TransportError::Timeout => CodexErr::Timeout,
            TransportError::Network(msg) | TransportError::Build(msg) => {
                CodexErr::Stream(msg, None)
            }
        },
        ApiError::RateLimit(msg) => CodexErr::Stream(msg, None),
    }
}

const ACTIVE_LIMIT_HEADER: &str = "x-codex-active-limit";
const REQUEST_ID_HEADER: &str = "x-request-id";
const OAI_REQUEST_ID_HEADER: &str = "x-oai-request-id";
const CF_RAY_HEADER: &str = "cf-ray";

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn map_api_error_maps_server_overloaded() {
        let err = map_api_error(ApiError::ServerOverloaded);
        assert!(matches!(err, CodexErr::ServerOverloaded));
    }

    #[test]
    fn map_api_error_maps_server_overloaded_from_503_body() {
        let body = serde_json::json!({
            "error": {
                "code": "server_is_overloaded"
            }
        })
        .to_string();
        let err = map_api_error(ApiError::Transport(TransportError::Http {
            status: http::StatusCode::SERVICE_UNAVAILABLE,
            url: Some("http://example.com/v1/responses".to_string()),
            headers: None,
            body: Some(body),
        }));

        assert!(matches!(err, CodexErr::ServerOverloaded));
    }

    #[test]
    fn map_api_error_maps_usage_limit_limit_name_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            ACTIVE_LIMIT_HEADER,
            http::HeaderValue::from_static("codex_other"),
        );
        headers.insert(
            "x-codex-other-limit-name",
            http::HeaderValue::from_static("codex_other"),
        );
        let body = serde_json::json!({
            "error": {
                "type": "usage_limit_reached",
                "plan_type": "pro",
            }
        })
        .to_string();
        let err = map_api_error(ApiError::Transport(TransportError::Http {
            status: http::StatusCode::TOO_MANY_REQUESTS,
            url: Some("http://example.com/v1/responses".to_string()),
            headers: Some(headers),
            body: Some(body),
        }));

        let CodexErr::UsageLimitReached(usage_limit) = err else {
            panic!("expected CodexErr::UsageLimitReached, got {err:?}");
        };
        assert_eq!(
            usage_limit
                .rate_limits
                .as_ref()
                .and_then(|snapshot| snapshot.limit_name.as_deref()),
            Some("codex_other")
        );
    }

    #[test]
    fn map_api_error_does_not_fallback_limit_name_to_limit_id() {
        let mut headers = HeaderMap::new();
        headers.insert(
            ACTIVE_LIMIT_HEADER,
            http::HeaderValue::from_static("codex_other"),
        );
        let body = serde_json::json!({
            "error": {
                "type": "usage_limit_reached",
                "plan_type": "pro",
            }
        })
        .to_string();
        let err = map_api_error(ApiError::Transport(TransportError::Http {
            status: http::StatusCode::TOO_MANY_REQUESTS,
            url: Some("http://example.com/v1/responses".to_string()),
            headers: Some(headers),
            body: Some(body),
        }));

        let CodexErr::UsageLimitReached(usage_limit) = err else {
            panic!("expected CodexErr::UsageLimitReached, got {err:?}");
        };
        assert_eq!(
            usage_limit
                .rate_limits
                .as_ref()
                .and_then(|snapshot| snapshot.limit_name.as_deref()),
            None
        );
    }
}

fn extract_request_tracking_id(headers: Option<&HeaderMap>) -> Option<String> {
    extract_request_id(headers).or_else(|| extract_header(headers, CF_RAY_HEADER))
}

fn extract_request_id(headers: Option<&HeaderMap>) -> Option<String> {
    extract_header(headers, REQUEST_ID_HEADER)
        .or_else(|| extract_header(headers, OAI_REQUEST_ID_HEADER))
}

fn extract_header(headers: Option<&HeaderMap>, name: &str) -> Option<String> {
    headers.and_then(|map| {
        map.get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
    })
}

pub(crate) async fn auth_provider_from_auth(
    auth: Option<CodexAuth>,
    provider: &ModelProviderInfo,
) -> crate::error::Result<CoreAuthProvider> {
    if let Some(api_key) = provider.api_key()? {
        return Ok(CoreAuthProvider {
            token: Some(api_key),
            account_id: None,
        });
    }

    if let Some(token) = provider.experimental_bearer_token.clone() {
        return Ok(CoreAuthProvider {
            token: Some(token),
            account_id: None,
        });
    }

    if let Some(scope) = provider.azure_entra_scope() {
        let token = load_azure_entra_token(scope.as_str()).await?;
        return Ok(CoreAuthProvider {
            token: Some(token),
            account_id: None,
        });
    }

    if let Some(auth) = auth {
        let token = auth.get_token()?;
        Ok(CoreAuthProvider {
            token: Some(token),
            account_id: auth.get_account_id(),
        })
    } else {
        Ok(CoreAuthProvider {
            token: None,
            account_id: None,
        })
    }
}

async fn load_azure_entra_token(scope: &str) -> crate::error::Result<String> {
    if let Ok(token) = std::env::var(AZURE_OPENAI_ENTRA_TOKEN_ENV_VAR)
        && !token.trim().is_empty()
    {
        return Ok(token.trim().to_string());
    }

    let output = match run_azure_cli_access_token(["--scope", scope]).await {
        Ok(output) => output,
        Err(err) => {
            if let Some(resource) = scope.strip_suffix("/.default") {
                run_azure_cli_access_token(["--resource", resource]).await?
            } else {
                return Err(err);
            }
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let details = if stderr.is_empty() {
            "no error details".to_string()
        } else {
            stderr
        };
        return Err(CodexErr::Fatal(format!(
            "Azure Entra auth is enabled but `az account get-access-token` failed for scope `{scope}`: {details}"
        )));
    }

    let token = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if token.is_empty() {
        return Err(CodexErr::Fatal(format!(
            "Azure Entra auth is enabled but Azure CLI returned an empty token for scope `{scope}`."
        )));
    }

    Ok(token)
}

async fn run_azure_cli_access_token(
    scope_or_resource: [&str; 2],
) -> crate::error::Result<std::process::Output> {
    Command::new("az")
        .args([
            "account",
            "get-access-token",
            scope_or_resource[0],
            scope_or_resource[1],
            "--query",
            "accessToken",
            "--output",
            "tsv",
        ])
        .output()
        .await
        .map_err(|err| {
            CodexErr::Fatal(format!(
                "Azure Entra auth is enabled but Azure CLI token retrieval failed: {err}. \
Install Azure CLI and run `az login`, or set {AZURE_OPENAI_ENTRA_TOKEN_ENV_VAR}."
            ))
        })
}

#[derive(Debug, Deserialize)]
struct UsageErrorResponse {
    error: UsageErrorBody,
}

#[derive(Debug, Deserialize)]
struct UsageErrorBody {
    #[serde(rename = "type")]
    error_type: Option<String>,
    plan_type: Option<PlanType>,
    resets_at: Option<i64>,
}

#[derive(Clone, Default)]
pub(crate) struct CoreAuthProvider {
    token: Option<String>,
    account_id: Option<String>,
}

impl ApiAuthProvider for CoreAuthProvider {
    fn bearer_token(&self) -> Option<String> {
        self.token.clone()
    }

    fn account_id(&self) -> Option<String> {
        self.account_id.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    struct EnvVarGuard {
        key: &'static str,
        original: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let original = std::env::var(key).ok();
            // SAFETY: tests run serially and restore env after assertions.
            unsafe {
                std::env::set_var(key, value);
            }
            Self { key, original }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            // SAFETY: tests run serially and restore env after assertions.
            unsafe {
                match &self.original {
                    Some(value) => std::env::set_var(self.key, value),
                    None => std::env::remove_var(self.key),
                }
            }
        }
    }

    #[tokio::test]
    #[serial]
    async fn azure_entra_auth_uses_env_token_when_available() {
        let _guard = EnvVarGuard::set(AZURE_OPENAI_ENTRA_TOKEN_ENV_VAR, "test-entra-token");
        let provider = ModelProviderInfo {
            name: "Azure".to_string(),
            base_url: None,
            endpoint: Some("https://example.azure.com/openai/responses".to_string()),
            env_key: None,
            env_key_instructions: None,
            experimental_bearer_token: None,
            azure_entra_auth: true,
            azure_entra_scope: None,
            wire_api: crate::WireApi::Responses,
            query_params: None,
            http_headers: None,
            env_http_headers: None,
            request_max_retries: None,
            stream_max_retries: None,
            stream_idle_timeout_ms: None,
            requires_openai_auth: false,
            supports_websockets: false,
        };

        let auth = auth_provider_from_auth(None, &provider)
            .await
            .expect("azure token should resolve from env");

        assert_eq!(auth.bearer_token(), Some("test-entra-token".to_string()));
        assert_eq!(auth.account_id(), None);
    }
}
