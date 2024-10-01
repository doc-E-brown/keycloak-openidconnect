use std::sync::{Arc, Mutex};

use actix_web::web::{self, Data};
use actix_web::{get, post, App, HttpRequest, HttpResponse, HttpServer, Responder};
use auth_test::openid::{
    connect, create_client, get_bearer_token, validate_token, Client, RealmRole,
};
use openidconnect::{reqwest::async_http_client, TokenResponse};
use openidconnect::{
    AccessTokenHash, AuthorizationCode, Nonce, OAuth2TokenResponse, PkceCodeVerifier,
    TokenIntrospectionResponse,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Params {
    pub state: String,
    pub session_state: String,
    pub code: String,
    pub iss: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tokens {
    pub access_token: String,
    pub id_token: String,
    pub refresh_token: String,
}

#[get("/read")]
async fn read(data: Data<AppData>, req: HttpRequest) -> impl Responder {
    if let Ok(bearer_token) = get_bearer_token(&req) {
        if let Ok(intro_response) = validate_token(&data.openapi_client, bearer_token).await {
            if intro_response.active() {
                let expected_role: String = RealmRole::RealmReadRole.into();
                let ef = intro_response.extra_fields();

                if ef
                    .realm_access
                    .clone()
                    .unwrap()
                    .roles
                    .contains(&expected_role)
                {
                    return HttpResponse::Ok().json(intro_response);
                }
            } else {
                return HttpResponse::Unauthorized().finish();
            }
        }
    }

    HttpResponse::InternalServerError().finish()
}

#[post("/write")]
async fn write(data: Data<AppData>, req: HttpRequest) -> impl Responder {
    println!("Write");
    if let Ok(bearer_token) = get_bearer_token(&req) {
        if let Ok(intro_response) = validate_token(&data.openapi_client, bearer_token).await {
            if intro_response.active() {
                let expected_role: String = RealmRole::RealmWriteRole.into();
                let ef = intro_response.extra_fields();

                if ef
                    .realm_access
                    .clone()
                    .unwrap()
                    .roles
                    .contains(&expected_role)
                {
                    return HttpResponse::Ok().json(intro_response);
                }
            } else {
                return HttpResponse::Unauthorized().finish();
            }
        }
    }

    HttpResponse::InternalServerError().finish()
}

#[get("/")]
async fn index(data: Data<AppData>, state: Option<web::Query<OAuth2Params>>) -> impl Responder {
    println!("Index");
    if let Some(state) = state {
        let (pkce_verifier, nonce) = {
            let pkce_verifier = data.pkce_verifier.clone();
            let pkce_verifier = pkce_verifier.lock().unwrap();

            let nonce = data.nonce.clone();
            let nonce = nonce.lock().unwrap();

            (pkce_verifier.clone(), nonce.clone())
        };

        // Get the access and ID token
        let token_response = match data
            .openapi_client
            .exchange_code(AuthorizationCode::new(state.code.clone()))
            .set_pkce_verifier(PkceCodeVerifier::new(
                pkce_verifier.unwrap_or_default().to_string(),
            ))
            .request_async(async_http_client)
            .await
        {
            Ok(resp) => resp,
            Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
        };

        let token = token_response.id_token().unwrap();

        let claims = token
            .claims(
                &data.openapi_client.id_token_verifier(),
                &Nonce::new(nonce.unwrap_or_default()),
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

        let tokens = Tokens {
            access_token: token_response.access_token().secret().to_string(),
            id_token: token.to_string(),
            refresh_token: token_response.refresh_token().unwrap().secret().to_string(),
        };

        HttpResponse::Ok().json(tokens)
    } else {
        // Need to login
        println!("Need to redirect");
        let (auth_url, _csrf_token, pkce_verifier, nonce) =
            connect(&data.openapi_client).await.unwrap();
        let mut data_pkce_verifier = data.pkce_verifier.lock().unwrap();
        *data_pkce_verifier = Some(pkce_verifier.secret().to_string());

        let mut data_nonce = data.nonce.lock().unwrap();
        *data_nonce = Some(nonce.secret().to_string());

        HttpResponse::TemporaryRedirect()
            .append_header(("Location", auth_url.to_string()))
            .finish()
    }
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
            .service(index)
            .service(write)
            .service(read)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
