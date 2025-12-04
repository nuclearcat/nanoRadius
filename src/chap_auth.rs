use md5::{Digest, Md5};

use crate::user_db::UserDb;

pub fn verify_chap_password(
    username: &str,
    chap_payload: &[u8],
    challenge: &[u8],
    db: &UserDb,
) -> bool {
    if chap_payload.len() < 17 {
        return false;
    }
    let chap_id = chap_payload[0];
    let response = &chap_payload[1..];
    let Some(clear) = db.get_password(username) else {
        return false;
    };
    let mut ctx = Md5::new();
    ctx.update([chap_id]);
    ctx.update(clear.as_bytes());
    ctx.update(challenge);
    let digest = ctx.finalize();
    digest.as_slice() == response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_payload(id: u8, password: &str, challenge: &[u8]) -> Vec<u8> {
        let mut ctx = Md5::new();
        ctx.update([id]);
        ctx.update(password.as_bytes());
        ctx.update(challenge);
        let digest = ctx.finalize();
        let mut out = Vec::new();
        out.push(id);
        out.extend_from_slice(digest.as_slice());
        out
    }

    fn test_db() -> UserDb {
        let mut db = std::collections::HashMap::new();
        db.insert("alice".to_string(), "secret".to_string());
        UserDb::from_map(db)
    }

    #[test]
    fn accepts_valid_chap_response() {
        let challenge = [0x55u8; 16];
        let payload = build_payload(1, "secret", &challenge);
        let db = test_db();

        assert!(verify_chap_password("alice", &payload, &challenge, &db));
    }

    #[test]
    fn rejects_wrong_password() {
        let challenge = [0x33u8; 16];
        let payload = build_payload(7, "wrong", &challenge);
        let db = test_db();

        assert!(!verify_chap_password("alice", &payload, &challenge, &db));
    }

    #[test]
    fn rejects_when_user_missing() {
        let challenge = [0x11u8; 16];
        let payload = build_payload(3, "secret", &challenge);
        let db = test_db();

        assert!(!verify_chap_password("bob", &payload, &challenge, &db));
    }
}
