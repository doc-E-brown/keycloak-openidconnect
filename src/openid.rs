use actix_web::HttpRequest;
use openidconnect::{
    core::{
        CoreAuthDisplay, CoreAuthPrompt, CoreAuthenticationFlow, CoreErrorResponseType,
        CoreGenderClaim, CoreJsonWebKey, CoreJsonWebKeyType, CoreJsonWebKeyUse,
        CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreProviderMetadata,
        CoreRevocableToken, CoreRevocationErrorResponse, CoreTokenResponse, CoreTokenType,
    },
    reqwest::async_http_client,
    url::Url,
    AccessToken, ClientId, ClientSecret, CsrfToken, EmptyAdditionalClaims, ExtraTokenFields,
    IntrospectionRequest, IntrospectionUrl, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, RevocationUrl, Scope, StandardErrorResponse, StandardTokenIntrospectionResponse,
};

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RealmRole {
    RealmReadRole,
    RealmWriteRole,
}

impl From<RealmRole> for String {
    fn from(value: RealmRole) -> Self {
        match value {
            RealmRole::RealmReadRole => "Realm-Read-Role".to_string(),
            RealmRole::RealmWriteRole => "Realm-Write-Role".to_string(),
        }
    }
}

impl TryFrom<String> for RealmRole {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        match value.to_lowercase().as_str() {
            "realm-read-role" => Ok(RealmRole::RealmReadRole),
            "realm-write-role" => Ok(RealmRole::RealmWriteRole),
            _ => Err(anyhow::anyhow!("Invalid realm role")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RealmAccess {
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealmAccessClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_access: Option<RealmAccess>,
}
impl ExtraTokenFields for RealmAccessClaims {}

pub type RealmIntrospectionRequest<'a> = IntrospectionRequest<
    'a,
    StandardErrorResponse<CoreErrorResponseType>,
    RealmTokenIntrospectionResponse,
    CoreTokenType,
>;
pub type RealmTokenIntrospectionResponse =
    StandardTokenIntrospectionResponse<RealmAccessClaims, CoreTokenType>;

pub type Client = openidconnect::Client<
    EmptyAdditionalClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
    CoreJsonWebKeyUse,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    CoreTokenResponse,
    CoreTokenType,
    RealmTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
>;

pub async fn create_client() -> Result<Client> {
    let provider_metadata = CoreProviderMetadata::discover_async(
        IssuerUrl::new("http://localhost:5100/realms/auth-test".to_string())?,
        async_http_client,
    )
    .await?;

    println!("Provider metadata: {:?}", provider_metadata);

    // Create an OpenID Connect client by specifying the client ID, client secret, authorization URL
    // and token URL.
    let client = Client::from_provider_metadata(
        provider_metadata,
        ClientId::new("demo-client".to_string()),
        Some(ClientSecret::new(
            "QGiQyQkQsYHTi5k4k98YIl5uFBpqknT4".to_string(),
        )),
    )
    // Set the URL the user will be redirected to after the authorization process.
    .set_redirect_uri(RedirectUrl::new("http://localhost:8080/".to_string())?)
    .set_revocation_uri(RevocationUrl::new(
        "http://localhost:5100/realms/auth-test/protocol/openid-connect/revoke".to_string(),
    )?)
    .set_introspection_uri(IntrospectionUrl::new(
        "http://localhost:5100/realms/auth-test/protocol/openid-connect/token/introspect"
            .to_string(),
    )?);

    Ok(client)
}

// pub async

pub async fn connect(client: &Client) -> Result<(Url, CsrfToken, PkceCodeVerifier, Nonce)> {
    // Generate a PKCE challenge.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, csrf_token, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        // Set the desired scopes.
        .add_scope(Scope::new("openid email profile".to_string()))
        // Set the PKCE code challenge.
        .set_pkce_challenge(pkce_challenge)
        .url();

    Ok((auth_url, csrf_token, pkce_verifier, nonce))
}

pub async fn validate_token(
    client: &Client,
    bearer_token: String,
) -> Result<RealmTokenIntrospectionResponse> {
    let access_token = AccessToken::new(bearer_token);
    let intro_request = client.introspect(&access_token).unwrap();
    let intro_response: RealmTokenIntrospectionResponse =
        intro_request.request_async(async_http_client).await?;

    Ok(intro_response)
}

pub fn get_bearer_token(req: &HttpRequest) -> Result<String> {
    req.headers()
        .get("Authorization")
        .map(|value| {
            value
                .as_bytes()
                .split(|&byte| byte == b' ')
                .nth(1)
                .map(|token| String::from_utf8(token.to_vec()).unwrap())
        })
        .ok_or(anyhow::anyhow!("Authorization header not found"))?
        .ok_or(anyhow::anyhow!("Bearer token not found"))
}
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_realm_roles() {
        let role: String = RealmRole::RealmReadRole.into();
        assert_eq!(role, "Realm-Read-Role".to_string());

        let role: RealmRole = RealmRole::try_from("Realm-Read-Role".to_string()).unwrap();
        assert_eq!(role, RealmRole::RealmReadRole);
    }
}
