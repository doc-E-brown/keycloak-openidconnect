use std::{
    io::Empty,
    ops::Add,
    str::FromStr,
    sync::{Arc, Mutex},
};

use actix_web::{
    body::BoxBody,
    get, post,
    web::{self, Data, Redirect},
    App, HttpMessage, HttpRequest, HttpResponse, HttpServer, Responder,
};
use auth_test::openid::{
    connect, create_client, Client, RealmAccessClaims, RealmAccessIdTokenClaims,
    RealmCodeTokenRequest, RealmIntrospectionRequest, RealmTokenIntrospectionResponse,
    RealmTokenResponse,
};
use openidconnect::{
    core::{
        CoreClient, CoreGenderClaim, CoreIdToken, CoreIdTokenClaims, CoreJsonWebKey,
        CoreJsonWebKeyType, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm,
        CoreTokenIntrospectionResponse, CoreTokenType, CoreUserInfoClaims,
    },
    AccessToken, AccessTokenHash, AdditionalClaims, AuthorizationCode, EmptyAdditionalClaims,
    EmptyExtraTokenFields, ExtraTokenFields, GenderClaim, IdToken, IdTokenClaims, Nonce,
    OAuth2TokenResponse, PkceCodeVerifier, StandardClaims, StandardTokenIntrospectionResponse,
    TokenIntrospectionResponse, UserInfoClaims,
};
use openidconnect::{reqwest::async_http_client, TokenResponse};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Params {
    pub state: String,
    pub session_state: String,
    pub code: String,
    pub iss: String,
}

#[get("/home")]
async fn home(data: Data<AppData>, req: HttpRequest) -> impl Responder {
    let pkce_verifier = data.pkce_verifier.clone();
    let pkce_verifier = pkce_verifier.lock().unwrap();

    let nonce = data.nonce.clone();
    let nonce = nonce.lock().unwrap();

    let bearer_token = req
        .headers()
        .get("Authorization")
        .map(|value| {
            value
                .as_bytes()
                .split(|&byte| byte == b' ')
                .nth(1)
                .map(|token| String::from_utf8(token.to_vec()).unwrap())
        })
        .unwrap()
        .unwrap();

    // get the access token
    /*     let access_token: IdToken<
           CustomClaims
           CoreGenderClaim,
           CoreJweContentEncryptionAlgorithm,
           CoreJwsSigningAlgorithm,
           CoreJsonWebKeyType,
       > = IdToken::from_str(&bearer_token).unwrap();
       let claims = access_token
           .claims(
               &data.openapi_client.id_token_verifier(),
               &Nonce::new(nonce.as_ref().unwrap().to_string()),
           )
           .unwrap();
    */
    HttpResponse::Ok()
}

#[get("/read")]
async fn read(data: Data<AppData>, req: HttpRequest) -> impl Responder {
    let bearer_token = req
        .headers()
        .get("Authorization")
        .map(|value| {
            value
                .as_bytes()
                .split(|&byte| byte == b' ')
                .nth(1)
                .map(|token| String::from_utf8(token.to_vec()).unwrap())
        })
        .unwrap()
        .unwrap();

    // get the access token
    let access_token = AccessToken::new(bearer_token);
    let intro_request = data.openapi_client.introspect(&access_token).unwrap();
    let intro_response: RealmTokenIntrospectionResponse = intro_request
        .request_async(async_http_client)
        .await
        .unwrap();
    let ef = intro_response.extra_fields();
    println!("Extra fields: {:?}", ef);
    HttpResponse::Ok().json(intro_response)
}

#[get("/")]
async fn index(data: Data<AppData>, state: Option<web::Query<OAuth2Params>>) -> impl Responder {
    println!("/");
    if let Some(state) = state {
        println!("State");

        let pkce_verifier = data.pkce_verifier.clone();
        let pkce_verifier = pkce_verifier.lock().unwrap();

        let nonce = data.nonce.clone();
        let nonce = nonce.lock().unwrap();

        // Get the access and ID token
        let token_response = data
            .openapi_client
            .exchange_code(AuthorizationCode::new(state.code.clone()))
            .set_pkce_verifier(PkceCodeVerifier::new(
                pkce_verifier.as_ref().unwrap().to_string(),
            ))
            .request_async(async_http_client)
            .await
            .unwrap();
        let token = token_response.id_token().unwrap();
        /*         let id_token = IdToken::from_str(&token.to_string()).unwrap();
               let claims: IdTokenClaims<CustomClaims, CoreGenderClaim> =
                   id_token.claims(verifier, nonce_verifier).unwrap();
        */
        println!("access_token: {:#?} ", token_response.access_token());

        let claims = token
            .claims(
                &data.openapi_client.id_token_verifier(),
                &Nonce::new(nonce.as_ref().unwrap().to_string()),
            )
            .unwrap();

        // Verify the access token hash to ensure that the access token hasn't been substituted for
        // another user's.
        if let Some(expected_access_token_hash) = claims.access_token_hash() {
            let actual_access_token_hash = AccessTokenHash::from_token(
                token_response.access_token(),
                &token.signing_alg().unwrap(),
            )
            .unwrap();
            if actual_access_token_hash != *expected_access_token_hash {
                panic!("Invalid access token hash");
            }
        }

        // The authenticated user's identity is now available. See the IdTokenClaims struct for a
        // complete listing of the available claims.
        println!(
            "User {} with e-mail address {} has authenticated successfully",
            claims.subject().as_str(),
            claims
                .email()
                .map(|email| email.as_str())
                .unwrap_or("<not provided>"),
        );

        println!("Claims: {:?}", claims);
        HttpResponse::Ok().body(token.to_string())
    } else {
        // Need to login
        println!("Need to redirect");
        let (auth_url, _csrf_token, pkce_verifier, nonce) =
            connect(&data.openapi_client).await.unwrap();
        let mut data_pkce_verifier = data.pkce_verifier.lock().unwrap();
        *data_pkce_verifier = Some(pkce_verifier.secret().to_string());

        let mut data_nonce = data.nonce.lock().unwrap();
        *data_nonce = Some(nonce.secret().to_string());
        println!("Redirect to {}", auth_url.to_string());
        HttpResponse::TemporaryRedirect()
            .append_header(("Location", auth_url.to_string()))
            .finish()
    }
}

#[get("/logout")]
async fn logout() -> impl Responder {
    HttpResponse::Ok().body("Logout")
}

#[post("/write")]
async fn write(req_body: String) -> impl Responder {
    HttpResponse::Ok().body(req_body)
}

#[derive(Debug, Clone)]
pub struct AppData {
    pub openapi_client: Client,
    pub pkce_verifier: Arc<Mutex<Option<String>>>,
    pub nonce: Arc<Mutex<Option<String>>>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let app_data = AppData {
        openapi_client: create_client().await.unwrap(),
        pkce_verifier: Arc::new(Mutex::new(None)),
        nonce: Arc::new(Mutex::new(None)),
    };

    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(app_data.clone()))
            .service(home)
            .service(index)
            .service(logout)
            .service(write)
            .service(read)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
