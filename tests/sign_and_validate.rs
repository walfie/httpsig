use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use std::error::Error;

// Values taken from:
// https://tools.ietf.org/html/draft-cavage-http-signatures-10#appendix-C
const PUBLIC_PEM: &'static [u8] = br#"-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C3
6rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6
Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJw
oYi+1hqp1fIekaxsyQIDAQAB
-----END PUBLIC KEY-----"#;

const PRIVATE_PEM: &'static [u8] = br#"-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF
NUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6Z4UMR7EOcpfdUE9Hf3m/hs+F
UR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJwoYi+1hqp1fIekaxsyQIDAQAB
AoGBAJR8ZkCUvx5kzv+utdl7T5MnordT1TvoXXJGXK7ZZ+UuvMNUCdN2QPc4sBiA
QWvLw1cSKt5DsKZ8UETpYPy8pPYnnDEz2dDYiaew9+xEpubyeW2oH4Zx71wqBtOK
kqwrXa/pzdpiucRRjk6vE6YY7EBBs/g7uanVpGibOVAEsqH1AkEA7DkjVH28WDUg
f1nqvfn2Kj6CT7nIcE3jGJsZZ7zlZmBmHFDONMLUrXR/Zm3pR5m0tCmBqa5RK95u
412jt1dPIwJBANJT3v8pnkth48bQo/fKel6uEYyboRtA5/uHuHkZ6FQF7OUkGogc
mSJluOdc5t6hI1VsLn0QZEjQZMEOWr+wKSMCQQCC4kXJEsHAve77oP6HtG/IiEn7
kpyUXRNvFsDE0czpJJBvL/aRFUJxuRK91jhjC68sA7NsKMGg5OXb5I5Jj36xAkEA
gIT7aFOYBFwGgQAQkWNKLvySgKbAZRTeLBacpHMuQdl1DfdntvAyqpAZ0lY0RKmW
G6aFKaqQfOXKCyWoUiVknQJAXrlgySFci/2ueKlIE1QqIiLSZ8V8OlpFLRnb1pzI
7U1yQXnTAEFYM560yJlzUpOb1V4cScGd365tiSMvxLOvTA==
-----END RSA PRIVATE KEY-----"#;

const HTTP_REQUEST: &'static [u8] = br#"POST /foo?param=value&pet=dog HTTP/1.1
Host: example.com
Date: Sun, 05 Jan 2014 21:31:40 GMT
Content-Type: application/json
Digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
Content-Length: 18

{"hello": "world"}"#;

type BoxError = Box<dyn Error + Send + Sync>;

// Adds signature header to a request and verifies that the signature is valid
fn verify(request: &[u8], public_key: &[u8], signature_header: &str) -> Result<(), BoxError> {
    let public_key = PKey::public_key_from_pem(public_key)?;
    let signature_header = signature_header.parse()?;

    let mut request = parse_request(request);
    request.headers_mut().insert("signature", signature_header);

    Ok(assert!(httpsig::verify_request(
        &request,
        MessageDigest::sha256(),
        &public_key
    )?))
}

// If a list of headers is not included, the date is the only header that is signed by default.
// https://tools.ietf.org/html/draft-cavage-http-signatures-10#appendix-C.1
#[test]
fn verify_default() -> Result<(), BoxError> {
    verify(
        HTTP_REQUEST,
        PUBLIC_PEM,
        r#"keyId="Test",algorithm="rsa-sha256",signature="SjWJWbWN7i0wzBvtPl8rbASWz5xQW6mcJmn+ibttBqtifLN7Sazz6m79cNfwwb8DMJ5cou1s7uEGKKCs+FLEEaDV5lp7q25WqS+lavg7T8hc0GppauB6hbgEKTwblDHYGEtbGmtdHgVCk9SuS13F0hZ8FD0k/5OxEPXe5WozsbM=""#
    )
}

// The minimum recommended data to sign is the (request-target), host, and date.
// https://tools.ietf.org/html/draft-cavage-http-signatures-10#appendix-C.2
#[test]
fn verify_basic() -> Result<(), BoxError> {
    verify(
        HTTP_REQUEST,
        PUBLIC_PEM,
        r#"keyId="Test",algorithm="rsa-sha256",headers="(request-target) host date",signature="qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7ndmw2iicw3HMbe8VfEdKFYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0=""#
    )
}

// A strong signature including all of the headers and a digest of the body of the HTTP request
// https://tools.ietf.org/html/draft-cavage-http-signatures-10#appendix-C.3
#[test]
fn verify_all_headers() -> Result<(), BoxError> {
    verify(
        HTTP_REQUEST,
        PUBLIC_PEM,
        r#"keyId="Test",algorithm="rsa-sha256",headers="(request-target) host date content-type digest content-length",signature="vSdrb+dS3EceC9bcwHSo4MlyKS59iFIrhgYkz8+oVLEEzmYZZvRs8rgOp+63LEM3v+MFHB32NfpB2bEKBIvB1q52LaEUHFv120V01IL+TAD48XaERZFukWgHoBTLMhYS2Gb51gWxpeIq8knRmPnYePbF5MOkR0Zkly4zKH7s1dE=""#
    )
}

#[test]
fn sign_all_headers() -> Result<(), BoxError> {
    let mut request = parse_request(HTTP_REQUEST);
    let private_key = PKey::private_key_from_pem(PRIVATE_PEM)?;
    let public_key = PKey::public_key_from_pem(PUBLIC_PEM)?;

    httpsig::add_signature_header(&mut request, "Test", MessageDigest::sha256(), &private_key)?;
    assert_eq!(
        request.headers().get("signature").unwrap(),

        // Excluding `algorithm` because it's not required
        r#"keyId="Test",headers="(request-target) host date content-type digest content-length",signature="vSdrb+dS3EceC9bcwHSo4MlyKS59iFIrhgYkz8+oVLEEzmYZZvRs8rgOp+63LEM3v+MFHB32NfpB2bEKBIvB1q52LaEUHFv120V01IL+TAD48XaERZFukWgHoBTLMhYS2Gb51gWxpeIq8knRmPnYePbF5MOkR0Zkly4zKH7s1dE=""#
    );

    assert!(httpsig::verify_request(
        &request,
        MessageDigest::sha256(),
        &public_key
    )?);

    Ok(())
}

fn parse_request<'a>(buf: &'a [u8]) -> http::Request<&'a [u8]> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    let bytes_parsed = req.parse(buf).expect("failed to parse request").unwrap() as usize;

    let version = match req.version.expect("no version") {
        0 => http::version::Version::HTTP_10,
        1 => http::version::Version::HTTP_11,
        other => panic!(format!("unexpected HTTP version {}", other)),
    };

    let mut builder = http::Request::builder();
    builder
        .method(req.method.expect("no method"))
        .uri(req.path.expect("no path"))
        .version(version);

    for header in req.headers {
        builder.header(header.name, header.value);
    }

    builder
        .body(&buf[bytes_parsed..])
        .expect("failed to create HTTP request")
}
