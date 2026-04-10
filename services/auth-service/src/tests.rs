use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use phantomgrid_types::{JwtClaims, UserRole};
use uuid::Uuid;

#[test]
fn test_jwt_generate_and_verify() {
    let now = Utc::now().timestamp() as usize;
    let claims = JwtClaims {
        sub: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        role: UserRole::Analyst,
        iat: now,
        exp: (Utc::now() + Duration::minutes(15)).timestamp() as usize,
        jti: Some(Uuid::new_v4().to_string()),
    };
    let key = EncodingKey::from_secret(b"test-secret");
    let dec = DecodingKey::from_secret(b"test-secret");
    let token = jsonwebtoken::encode(&Header::new(Algorithm::HS256), &claims, &key).expect("encode");
    let out = jsonwebtoken::decode::<JwtClaims>(&token, &dec, &Validation::new(Algorithm::HS256)).expect("decode");
    assert_eq!(out.claims.sub, claims.sub);
}

#[test]
fn test_jwt_expired_rejected() {
    let claims = JwtClaims {
        sub: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        role: UserRole::Analyst,
        iat: (Utc::now() - Duration::minutes(10)).timestamp() as usize,
        exp: (Utc::now() - Duration::minutes(2)).timestamp() as usize,
        jti: Some(Uuid::new_v4().to_string()),
    };
    let key = EncodingKey::from_secret(b"test-secret");
    let dec = DecodingKey::from_secret(b"test-secret");
    let token = jsonwebtoken::encode(&Header::new(Algorithm::HS256), &claims, &key).expect("encode");
    let out = jsonwebtoken::decode::<JwtClaims>(&token, &dec, &Validation::new(Algorithm::HS256));
    assert!(out.is_err());
}
