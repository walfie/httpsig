use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // Values taken from:
    // https://tools.ietf.org/html/draft-cavage-http-signatures-10#appendix-C
    let input = br#"POST /foo?param=value&pet=dog HTTP/1.1
Host: example.com
Date: Sun, 05 Jan 2014 21:31:40 GMT
Content-Type: application/json
Digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
Content-Length: 18

{"hello": "world"}"#;

    let public_pem = br#"-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C3
6rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6
Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJw
oYi+1hqp1fIekaxsyQIDAQAB
-----END PUBLIC KEY-----"#;

    let private_pem = br#"-----BEGIN RSA PRIVATE KEY-----
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
    let mut request = parse_request(input);

    let private_key = PKey::private_key_from_pem(private_pem)?;
    let public_key = PKey::public_key_from_pem(public_pem)?;

    let signature =
        httpsig::create_signature_header(&request, "Test", MessageDigest::sha256(), &private_key)?;

    request
        .headers_mut()
        .insert("signature", signature.parse()?);

    if let Some(parts) = httpsig::parse_signature_parts(&signature) {
        assert!(httpsig::validate_signature_parts(
            &request,
            &parts,
            MessageDigest::sha256(),
            &public_key
        )?);
    } else {
        panic!("Failed to parse parts {:?}", signature);
    }

    Ok(())
}

// Not returning a `Result` here because it's out of scope for the library
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
