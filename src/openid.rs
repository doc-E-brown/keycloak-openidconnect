use openidconnect::{
    core::{
        CoreAuthDisplay, CoreAuthPrompt, CoreAuthenticationFlow, CoreClient, CoreErrorResponseType,
        CoreGenderClaim, CoreIdTokenClaims, CoreJsonWebKey, CoreJsonWebKeyType, CoreJsonWebKeyUse,
        CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreProviderMetadata,
        CoreRevocableToken, CoreRevocationErrorResponse, CoreTokenIntrospectionResponse,
        CoreTokenResponse, CoreTokenType,
    },
    reqwest::async_http_client,
    url::Url,
    AdditionalClaims, ClientId, ClientSecret, CodeTokenRequest, CsrfToken, EmptyExtraTokenFields,
    ExtraTokenFields, HttpResponse, IdTokenClaims, IdTokenFields, IntrospectionRequest,
    IntrospectionUrl, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    StandardErrorResponse, StandardTokenIntrospectionResponse, StandardTokenResponse,
};

use anyhow::Result;
use serde::{Deserialize, Serialize};

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

impl AdditionalClaims for RealmAccess {}
impl AdditionalClaims for RealmAccessClaims {}
impl ExtraTokenFields for RealmAccessClaims {}

#[derive(Debug, Serialize, Deserialize)]
struct CustomClaims {
    #[serde(flatten)]
    standard_claims: CoreIdTokenClaims,
    #[serde(flatten)]
    additional_claims: RealmAccessClaims,
}

impl AdditionalClaims for CustomClaims {}

pub type RealmAccessIdTokenFields = IdTokenFields<
    RealmAccessClaims,
    EmptyExtraTokenFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
>;

pub type RealmAccessIdTokenClaims = IdTokenClaims<RealmAccessClaims, CoreGenderClaim>;

pub type RealmTokenResponse = StandardTokenResponse<RealmAccessIdTokenFields, CoreTokenType>;
pub type RealmCodeTokenRequest<'a> = CodeTokenRequest<
    'a,
    StandardErrorResponse<CoreErrorResponseType>,
    RealmTokenResponse,
    CoreTokenType,
>;

pub type RealmIntrospectionRequest<'a> = IntrospectionRequest<
    'a,
    StandardErrorResponse<CoreErrorResponseType>,
    RealmTokenResponse,
    CoreTokenType,
>;
pub type RealmTokenIntrospectionResponse =
    StandardTokenIntrospectionResponse<RealmAccessClaims, CoreTokenType>;

pub type Client = openidconnect::Client<
    RealmAccessClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
    CoreJsonWebKeyUse,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    RealmTokenResponse,
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
