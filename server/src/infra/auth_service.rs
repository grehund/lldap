use std::collections::{hash_map::DefaultHasher, HashSet};
use std::hash::{Hash, Hasher};
use std::pin::Pin;
use std::task::Poll;

use actix_web::{
    cookie::{Cookie, SameSite},
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    error::{ErrorBadRequest, ErrorUnauthorized},
    web, FromRequest, HttpRequest, HttpResponse,
};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use anyhow::{bail, Context, Result};
use chrono::prelude::*;
use futures::future::{ok, Ready};
use futures_util::{FutureExt, TryFutureExt};
use hmac::Hmac;
use jwt::{SignWithKey, VerifyWithKey};
use log::*;
use sha2::Sha512;
use time::ext::NumericalDuration;

use lldap_auth::{login, password_reset, registration, JWTClaims};

use crate::{
    domain::{
        error::DomainError,
        handler::{BackendHandler, BindRequest, GroupIdAndName, LoginHandler, UserId},
        opaque_handler::OpaqueHandler,
    },
    infra::{
        tcp_backend_handler::*,
        tcp_server::{error_to_http_response, AppState},
    },
};

type Token<S> = jwt::Token<jwt::Header, JWTClaims, S>;
type SignedToken = Token<jwt::token::Signed>;

fn create_jwt(key: &Hmac<Sha512>, user: String, groups: HashSet<GroupIdAndName>) -> SignedToken {
    let claims = JWTClaims {
        exp: Utc::now() + chrono::Duration::days(1),
        iat: Utc::now(),
        user,
        groups: groups.into_iter().map(|g| g.1).collect(),
    };
    let header = jwt::Header {
        algorithm: jwt::AlgorithmType::Hs512,
        ..Default::default()
    };
    jwt::Token::new(header, claims).sign_with_key(key).unwrap()
}

fn parse_refresh_token(token: &str) -> std::result::Result<(u64, UserId), HttpResponse> {
    match token.split_once('+') {
        None => Err(HttpResponse::Unauthorized().body("Invalid refresh token")),
        Some((token, u)) => {
            let refresh_token_hash = {
                let mut s = DefaultHasher::new();
                token.hash(&mut s);
                s.finish()
            };
            Ok((refresh_token_hash, UserId::new(u)))
        }
    }
}

fn get_refresh_token(request: HttpRequest) -> std::result::Result<(u64, UserId), HttpResponse> {
    match (
        request.cookie("refresh_token"),
        request.headers().get("refresh-token"),
    ) {
        (Some(c), _) => parse_refresh_token(c.value()),
        (_, Some(t)) => parse_refresh_token(t.to_str().unwrap()),
        (None, None) => Err(HttpResponse::Unauthorized().body("Missing refresh token")),
    }
}

async fn get_refresh<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    let backend_handler = &data.backend_handler;
    let jwt_key = &data.jwt_key;
    let (refresh_token_hash, user) = match get_refresh_token(request) {
        Ok(t) => t,
        Err(http_response) => return http_response,
    };
    let res_found = data
        .backend_handler
        .check_token(refresh_token_hash, &user)
        .await;
    // Async closures are not supported yet.
    match res_found {
        Ok(found) => {
            if found {
                backend_handler.get_user_groups(&user).await
            } else {
                Err(DomainError::AuthenticationError(
                    "Invalid refresh token".to_string(),
                ))
            }
        }
        Err(e) => Err(e),
    }
    .map(|groups| create_jwt(jwt_key, user.to_string(), groups))
    .map(|token| {
        HttpResponse::Ok()
            .cookie(
                Cookie::build("token", token.as_str())
                    .max_age(1.days())
                    .path("/")
                    .http_only(true)
                    .same_site(SameSite::Strict)
                    .finish(),
            )
            .json(&login::ServerLoginResponse {
                token: token.as_str().to_owned(),
                refresh_token: None,
            })
    })
    .unwrap_or_else(error_to_http_response)
}

async fn get_password_reset_step1<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    let user_id = match request.match_info().get("user_id") {
        None => return HttpResponse::BadRequest().body("Missing user ID"),
        Some(id) => UserId::new(id),
    };
    let token = match data.backend_handler.start_password_reset(&user_id).await {
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
        Ok(None) => return HttpResponse::Ok().finish(),
        Ok(Some(token)) => token,
    };
    let user = match data.backend_handler.get_user_details(&user_id).await {
        Err(e) => {
            warn!("Error getting used details: {:#?}", e);
            return HttpResponse::Ok().finish();
        }
        Ok(u) => u,
    };
    if let Err(e) = super::mail::send_password_reset_email(
        &user.display_name,
        &user.email,
        &token,
        &data.server_url,
        &data.mail_options,
    ) {
        warn!("Error sending email: {:#?}", e);
        return HttpResponse::InternalServerError().body(format!("Could not send email: {}", e));
    }
    HttpResponse::Ok().finish()
}

async fn check_password_reset_token<'a, Backend>(
    backend_handler: &Backend,
    token: &Option<&'a str>,
) -> Result<Option<(&'a str, UserId)>, HttpResponse>
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    let token = match token {
        None => return Ok(None),
        Some(token) => token,
    };
    let user_id = match backend_handler
        .get_user_id_for_password_reset_token(token)
        .await
    {
        Err(_) => return Err(HttpResponse::Unauthorized().body("Invalid or expired token")),
        Ok(user_id) => user_id,
    };
    Ok(Some((token, user_id)))
}

async fn get_password_reset_step2<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    let (token, user_id) =
        match check_password_reset_token(&data.backend_handler, &request.match_info().get("token"))
            .await
        {
            Err(http_response) => return http_response,
            Ok(None) => return HttpResponse::BadRequest().body("Missing token"),
            Ok(Some(r)) => r,
        };
    let _ = data
        .backend_handler
        .delete_password_reset_token(token)
        .await;
    let groups = HashSet::new();
    let token = create_jwt(&data.jwt_key, user_id.to_string(), groups);
    HttpResponse::Ok()
        .cookie(
            Cookie::build("token", token.as_str())
                .max_age(5.minutes())
                // Cookie is only valid to reset the password.
                .path("/auth")
                .http_only(true)
                .same_site(SameSite::Strict)
                .finish(),
        )
        .json(&password_reset::ServerPasswordResetResponse {
            user_id: user_id.to_string(),
            token: token.as_str().to_owned(),
        })
}

async fn get_logout<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + 'static,
{
    let (refresh_token_hash, user) = match get_refresh_token(request) {
        Ok(t) => t,
        Err(http_response) => return http_response,
    };
    if let Err(response) = data
        .backend_handler
        .delete_refresh_token(refresh_token_hash)
        .map_err(error_to_http_response)
        .await
    {
        return response;
    };
    match data
        .backend_handler
        .blacklist_jwts(&user)
        .map_err(error_to_http_response)
        .await
    {
        Ok(new_blacklisted_jwts) => {
            let mut jwt_blacklist = data.jwt_blacklist.write().unwrap();
            for jwt in new_blacklisted_jwts {
                jwt_blacklist.insert(jwt);
            }
        }
        Err(response) => return response,
    };
    HttpResponse::Ok()
        .cookie(
            Cookie::build("token", "")
                .max_age(0.days())
                .path("/")
                .http_only(true)
                .same_site(SameSite::Strict)
                .finish(),
        )
        .cookie(
            Cookie::build("refresh_token", "")
                .max_age(0.days())
                .path("/auth")
                .http_only(true)
                .same_site(SameSite::Strict)
                .finish(),
        )
        .finish()
}

pub(crate) fn error_to_api_response<T>(error: DomainError) -> ApiResult<T> {
    ApiResult::Right(error_to_http_response(error))
}

pub type ApiResult<M> = actix_web::Either<web::Json<M>, HttpResponse>;

async fn opaque_login_start<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<login::ClientLoginStartRequest>,
) -> ApiResult<login::ServerLoginStartResponse>
where
    Backend: OpaqueHandler + 'static,
{
    data.backend_handler
        .login_start(request.into_inner())
        .await
        .map(|res| ApiResult::Left(web::Json(res)))
        .unwrap_or_else(error_to_api_response)
}

async fn get_login_successful_response<Backend>(
    data: &web::Data<AppState<Backend>>,
    name: &UserId,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler,
{
    // The authentication was successful, we need to fetch the groups to create the JWT
    // token.
    data.backend_handler
        .get_user_groups(name)
        .and_then(|g| async { Ok((g, data.backend_handler.create_refresh_token(name).await?)) })
        .await
        .map(|(groups, (refresh_token, max_age))| {
            let token = create_jwt(&data.jwt_key, name.to_string(), groups);
            let refresh_token_plus_name = refresh_token + "+" + name.as_str();

            HttpResponse::Ok()
                .cookie(
                    Cookie::build("token", token.as_str())
                        .max_age(1.days())
                        .path("/")
                        .http_only(true)
                        .same_site(SameSite::Strict)
                        .finish(),
                )
                .cookie(
                    Cookie::build("refresh_token", refresh_token_plus_name.clone())
                        .max_age(max_age.num_days().days())
                        .path("/auth")
                        .http_only(true)
                        .same_site(SameSite::Strict)
                        .finish(),
                )
                .json(&login::ServerLoginResponse {
                    token: token.as_str().to_owned(),
                    refresh_token: Some(refresh_token_plus_name),
                })
        })
        .unwrap_or_else(error_to_http_response)
}

async fn opaque_login_finish<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<login::ClientLoginFinishRequest>,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + OpaqueHandler + 'static,
{
    let name = match data
        .backend_handler
        .login_finish(request.into_inner())
        .await
    {
        Ok(n) => n,
        Err(e) => return error_to_http_response(e),
    };
    get_login_successful_response(&data, &name).await
}

fn parse_hash_list(response: &str) -> Result<password_reset::PasswordHashList> {
    use password_reset::*;
    let parse_line = |line: &str| -> Result<PasswordHashCount> {
        let split = line.trim().split(':').collect::<Vec<_>>();
        if let [hash, count] = &split[..] {
            if hash.len() == 35 {
                if let Ok(count) = str::parse::<u64>(count) {
                    return Ok(PasswordHashCount {
                        hash: hash.to_string(),
                        count,
                    });
                }
            }
        }
        bail!("Invalid password hash from API: {}", line)
    };
    Ok(PasswordHashList {
        hashes: response
            .split('\n')
            .map(parse_line)
            .collect::<Result<Vec<_>>>()?,
    })
}

async fn get_password_hash_list(
    hash: &str,
    api_key: &str,
) -> Result<password_reset::PasswordHashList> {
    use reqwest::*;
    let client = Client::new();
    let resp = client
        .get(format!("https://api.pwnedpasswords.com/range/{}", hash))
        .header(header::USER_AGENT, "LLDAP")
        .header("hibp-api-key", api_key)
        .send()
        .await
        .context("Could not get response from HIPB")?
        .text()
        .await?;
    parse_hash_list(&resp).context("Invalid HIPB response")
}

async fn check_password_pwned<Backend>(
    data: web::Data<AppState<Backend>>,
    request: HttpRequest,
    mut payload: web::Payload,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + OpaqueHandler + 'static,
{
    let has_reset_token = match check_password_reset_token(
        &data.backend_handler,
        &request
            .headers()
            .get("reset-token")
            .map(|v| v.to_str().unwrap()),
    )
    .await
    {
        Err(http_response) => return http_response,
        Ok(None) => false,
        Ok(_) => true,
    };
    if !has_reset_token
        && BearerAuth::from_request(&request, &mut payload.0)
            .await
            .ok()
            .and_then(|bearer| check_if_token_is_valid(&data, bearer.token()).ok())
            .is_none()
    {
        return HttpResponse::Unauthorized().finish();
    }
    if data.hipb_api_key.is_empty() {
        return HttpResponse::NotImplemented().body("No HIPB API key");
    }
    let parsed_request = match web::Json::<password_reset::PasswordPartialHash>::from_request(
        &request,
        &mut payload.0,
    )
    .await
    {
        Ok(p) => p,
        Err(_) => return HttpResponse::BadRequest().body("Bad request: invalid json"),
    };
    let hash = &parsed_request.partial_hash;
    if hash.len() != 5 || !hash.chars().all(|c| c.is_digit(16)) {
        return HttpResponse::BadRequest()
            .body(format!("Bad request: invalid hash format \"{}\"", hash));
    }
    match get_password_hash_list(hash, &data.hipb_api_key).await {
        Ok(hashes) => HttpResponse::Ok().json(hashes),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

async fn simple_login<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<login::ClientSimpleLoginRequest>,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + OpaqueHandler + LoginHandler + 'static,
{
    let user_id = UserId::new(&request.username);
    let bind_request = BindRequest {
        name: user_id.clone(),
        password: request.password.clone(),
    };

    if let Err(e) = data.backend_handler.bind(bind_request).await {
        return error_to_http_response(e);
    }

    get_login_successful_response(&data, &user_id).await
}

async fn opaque_register_start<Backend>(
    request: HttpRequest,
    mut payload: web::Payload,
    data: web::Data<AppState<Backend>>,
) -> ApiResult<registration::ServerRegistrationStartResponse>
where
    Backend: OpaqueHandler + 'static,
{
    let validation_result = match BearerAuth::from_request(&request, &mut payload.0)
        .await
        .ok()
        .and_then(|bearer| check_if_token_is_valid(&data, bearer.token()).ok())
    {
        Some(t) => t,
        None => {
            return ApiResult::Right(
                HttpResponse::Unauthorized().body("Not authorized to change the user's password"),
            )
        }
    };
    let registration_start_request =
        match web::Json::<registration::ClientRegistrationStartRequest>::from_request(
            &request,
            &mut payload.0,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                return ApiResult::Right(
                    HttpResponse::BadRequest().body(format!("Bad request: {:#?}", e)),
                )
            }
        }
        .into_inner();
    let user_id = &registration_start_request.username;
    validation_result.can_access(user_id);
    data.backend_handler
        .registration_start(registration_start_request)
        .await
        .map(|res| ApiResult::Left(web::Json(res)))
        .unwrap_or_else(error_to_api_response)
}

async fn opaque_register_finish<Backend>(
    data: web::Data<AppState<Backend>>,
    request: web::Json<registration::ClientRegistrationFinishRequest>,
) -> HttpResponse
where
    Backend: TcpBackendHandler + BackendHandler + OpaqueHandler + 'static,
{
    if let Err(e) = data
        .backend_handler
        .registration_finish(request.into_inner())
        .await
    {
        return error_to_http_response(e);
    }
    HttpResponse::Ok().finish()
}

pub struct CookieToHeaderTranslatorFactory;

impl<S> Transform<S, ServiceRequest> for CookieToHeaderTranslatorFactory
where
    S: Service<ServiceRequest, Response = ServiceResponse, Error = actix_web::Error>,
    S::Future: 'static,
{
    type Response = ServiceResponse;
    type Error = actix_web::Error;
    type InitError = ();
    type Transform = CookieToHeaderTranslator<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(CookieToHeaderTranslator { service })
    }
}

pub struct CookieToHeaderTranslator<S> {
    service: S,
}

impl<S> Service<ServiceRequest> for CookieToHeaderTranslator<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse, Error = actix_web::Error>,
    S::Future: 'static,
{
    type Response = ServiceResponse;
    type Error = actix_web::Error;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn core::future::Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        if let Some(token_cookie) = req.cookie("token") {
            if let Ok(header_value) = actix_http::header::HeaderValue::from_str(&format!(
                "Bearer {}",
                token_cookie.value()
            )) {
                req.headers_mut()
                    .insert(actix_http::header::AUTHORIZATION, header_value);
            } else {
                return async move {
                    Ok(req.error_response(ErrorBadRequest("Invalid token cookie")))
                }
                .boxed_local();
            }
        };

        Box::pin(self.service.call(req))
    }
}

pub struct ValidationResults {
    pub user: String,
    pub is_admin: bool,
}

impl ValidationResults {
    #[cfg(test)]
    pub fn admin() -> Self {
        Self {
            user: "admin".to_string(),
            is_admin: true,
        }
    }

    pub fn can_access(&self, user: &str) -> bool {
        self.is_admin || self.user == user
    }
}

pub(crate) fn check_if_token_is_valid<Backend>(
    state: &AppState<Backend>,
    token_str: &str,
) -> Result<ValidationResults, actix_web::Error> {
    let token: Token<_> = VerifyWithKey::verify_with_key(token_str, &state.jwt_key)
        .map_err(|_| ErrorUnauthorized("Invalid JWT"))?;
    if token.claims().exp.lt(&Utc::now()) {
        return Err(ErrorUnauthorized("Expired JWT"));
    }
    if token.header().algorithm != jwt::AlgorithmType::Hs512 {
        return Err(ErrorUnauthorized(format!(
            "Unsupported JWT algorithm: '{:?}'. Supported ones are: ['HS512']",
            token.header().algorithm
        )));
    }
    let jwt_hash = {
        let mut s = DefaultHasher::new();
        token_str.hash(&mut s);
        s.finish()
    };
    if state.jwt_blacklist.read().unwrap().contains(&jwt_hash) {
        return Err(ErrorUnauthorized("JWT was logged out"));
    }
    let is_admin = token.claims().groups.contains("lldap_admin");
    let (_, claims): (jwt::Header, JWTClaims) = token.into();
    Ok(ValidationResults {
        user: claims.user,
        is_admin,
    })
}

pub fn configure_server<Backend>(cfg: &mut web::ServiceConfig)
where
    Backend: TcpBackendHandler + LoginHandler + OpaqueHandler + BackendHandler + 'static,
{
    cfg.service(
        web::resource("/opaque/login/start").route(web::post().to(opaque_login_start::<Backend>)),
    )
    .service(
        web::resource("/opaque/login/finish").route(web::post().to(opaque_login_finish::<Backend>)),
    )
    .service(web::resource("/simple/login").route(web::post().to(simple_login::<Backend>)))
    .service(web::resource("/refresh").route(web::get().to(get_refresh::<Backend>)))
    .service(
        web::resource("/password/check")
            .wrap(CookieToHeaderTranslatorFactory)
            .route(web::post().to(check_password_pwned::<Backend>)),
    )
    .service(
        web::resource("/reset/step1/{user_id}")
            .route(web::get().to(get_password_reset_step1::<Backend>)),
    )
    .service(
        web::resource("/reset/step2/{token}")
            .route(web::get().to(get_password_reset_step2::<Backend>)),
    )
    .service(web::resource("/logout").route(web::get().to(get_logout::<Backend>)))
    .service(
        web::scope("/opaque/register")
            .wrap(CookieToHeaderTranslatorFactory)
            .service(
                web::resource("/start").route(web::post().to(opaque_register_start::<Backend>)),
            )
            .service(
                web::resource("/finish").route(web::post().to(opaque_register_finish::<Backend>)),
            ),
    );
}
