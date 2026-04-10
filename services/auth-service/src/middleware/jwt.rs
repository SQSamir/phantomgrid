use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
};
use jsonwebtoken::{decode, Algorithm, Validation};
use phantomgrid_types::JwtClaims;

use crate::AppState;

pub struct ValidatedClaims(pub JwtClaims);

impl FromRequestParts<AppState> for ValidatedClaims {
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let auth = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .ok_or((StatusCode::UNAUTHORIZED, "missing authorization"))?;

        let token = auth
            .strip_prefix("Bearer ")
            .ok_or((StatusCode::UNAUTHORIZED, "invalid authorization"))?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true;

        let claims = decode::<JwtClaims>(token, &state.dec, &validation)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid token"))?
            .claims;

        parts.extensions.insert(claims.clone());
        Ok(Self(claims))
    }
}
