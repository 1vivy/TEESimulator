#![allow(
    missing_docs,
    reason = "integration tests describe behavior in their names"
)]
#![allow(
    clippy::unwrap_used,
    reason = "fixture construction must fail immediately"
)]

use rka_rkp::{
    AttestationStatusClient, ClientError, HttpResponse, ResponseHeaders, STATUS_URL,
    StatusHttpTransport, StatusRequest, ValidationError,
};

#[derive(Debug)]
struct FakeStatusTransport {
    response: Option<Result<HttpResponse, ClientError>>,
    urls: Vec<String>,
}

impl StatusHttpTransport for FakeStatusTransport {
    fn get(&mut self, request: StatusRequest<'_>) -> Result<HttpResponse, ClientError> {
        self.urls.push(request.url.to_owned());
        self.response.take().ok_or(ClientError::Transport)?
    }
}

fn response(cache_control: &str, body: &str) -> HttpResponse {
    HttpResponse::new(
        200,
        ResponseHeaders::collect_bounded([("cache-control", cache_control)]).unwrap(),
        body.as_bytes().to_vec(),
    )
    .unwrap()
}

#[test]
fn fixed_status_endpoint_resolves_every_requested_serial_and_caches_until_expiry() {
    let transport = FakeStatusTransport {
        response: Some(Ok(response(
            "public, max-age=60",
            r#"{"entries":{"1a":{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}"#,
        ))),
        urls: Vec::new(),
    };
    let mut client = AttestationStatusClient::new(transport);

    let snapshot = client.snapshot_for(100, ["1a", "1b"]).unwrap();

    assert_eq!(
        snapshot.require_good(100, "1a"),
        Err(ValidationError::Revoked)
    );
    assert_eq!(snapshot.require_good(100, "1b"), Ok(()));
    assert_eq!(client.transport().urls, [STATUS_URL]);
    assert!(client.snapshot_for(159, ["1b"]).is_ok());
    assert_eq!(client.transport().urls, [STATUS_URL]);
}

#[test]
fn status_transport_and_schema_fail_closed() {
    for body in [
        "{}",
        r#"{"entries":{"1A":{"status":"REVOKED"}}}"#,
        r#"{"entries":{"1a":{"status":"GOOD"}}}"#,
        r#"{"entries":{"1a":{"status":"REVOKED","extra":true}}}"#,
        r#"{"entries":{"1a":{"status":"REVOKED"},"1a":{"status":"SUSPENDED"}}}"#,
    ] {
        let transport = FakeStatusTransport {
            response: Some(Ok(response("max-age=60", body))),
            urls: Vec::new(),
        };
        assert_eq!(
            AttestationStatusClient::new(transport).snapshot_for(100, ["1a"]),
            Err(ValidationError::Status)
        );
    }
    let transport = FakeStatusTransport {
        response: Some(Err(ClientError::Transport)),
        urls: Vec::new(),
    };
    assert_eq!(
        AttestationStatusClient::new(transport).snapshot_for(100, ["1a"]),
        Err(ValidationError::Status)
    );
}

#[test]
fn stale_cache_requires_a_fresh_bounded_response() {
    let transport = FakeStatusTransport {
        response: Some(Ok(response("max-age=1", r#"{"entries":{}}"#))),
        urls: Vec::new(),
    };
    let mut client = AttestationStatusClient::new(transport);
    assert!(client.snapshot_for(100, ["1a"]).is_ok());

    assert_eq!(
        client.snapshot_for(101, ["1a"]),
        Err(ValidationError::Status)
    );
}
