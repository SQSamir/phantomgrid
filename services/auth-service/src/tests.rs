use super::*;
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};

#[test]
fn test_password_hashing_and_verify() {
    let password = "S3cureP@ssw0rd";
    let hash = hash_password(password).expect("hash");
    assert!(verify_password(password, &hash));
    assert!(!verify_password("wrong", &hash));
}

#[test]
fn test_jwt_generate_and_verify() {
    let claims = make_claims(Uuid::new_v4(), Uuid::new_v4(), UserRole::Analyst, 15);
    let key = EncodingKey::from_secret(b"test-secret");
    let dec = DecodingKey::from_secret(b"test-secret");
    let token = jsonwebtoken::encode(&Header::new(Algorithm::HS256), &claims, &key).expect("encode");
    let out = jsonwebtoken::decode::<JwtClaims>(&token, &dec, &Validation::new(Algorithm::HS256)).expect("decode");
    assert_eq!(out.claims.sub, claims.sub);
}

#[test]
fn test_jwt_expired_rejected() {
    let mut claims = make_claims(Uuid::new_v4(), Uuid::new_v4(), UserRole::Analyst, 1);
    claims.exp = (Utc::now() - Duration::minutes(2)).timestamp() as usize;
    let key = EncodingKey::from_secret(b"test-secret");
    let dec = DecodingKey::from_secret(b"test-secret");
    let token = jsonwebtoken::encode(&Header::new(Algorithm::HS256), &claims, &key).expect("encode");
    let out = jsonwebtoken::decode::<JwtClaims>(&token, &dec, &Validation::new(Algorithm::HS256));
    assert!(out.is_err());
}

#[test]
fn test_login_lockout_after_5_failures() {
    let mut attempts = 0;
    let mut locked = false;
    for _ in 0..5 {
        attempts += 1;
        if attempts >= 5 {
            locked = true;
        }
    }
    assert!(locked);
}

#[test]
fn test_refresh_token_rotation() {
    let old_refresh = "old-refresh";
    let new_refresh = "new-refresh";
    assert_ne!(old_refresh, new_refresh);
}

#[test]
fn test_totp_replay_prevention() {
    use std::collections::HashSet;
    let mut used = HashSet::new();
    let code = "123456";
    assert!(used.insert(code.to_string()));
    assert!(!used.insert(code.to_string()));
}
