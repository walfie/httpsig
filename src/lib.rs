use openssl::hash::MessageDigest;
use openssl::pkey::{HasPrivate, HasPublic, PKeyRef};
use openssl::sign::{Signer, Verifier};
use std::error::Error;
use std::fmt::Write as _;
use std::io::Write as _;

pub fn verify_request<'a, T>(
    request: &http::Request<T>,
    digest: MessageDigest,
    public_key: &PKeyRef<impl HasPublic>,
) -> Result<bool, Box<dyn Error + Send + Sync>> {
    if let Some(signature) = request.headers().get("signature") {
        if let Some(parts) = parse_signature_parts(signature.to_str()?) {
            verify_signature_parts(request, &parts, digest, public_key)
        } else {
            Ok(false)
        }
    } else {
        Ok(false)
    }
}

pub fn verify_signature_parts<'a, T>(
    request: &http::Request<T>,
    parts: &SignatureParts<'a>,
    digest: MessageDigest,
    public_key: &PKeyRef<impl HasPublic>,
) -> Result<bool, Box<dyn Error + Send + Sync>> {
    let signature = base64::decode(parts.signature)?;

    let mut verifier = Verifier::new(digest, public_key)?;
    let mut to_verify: Vec<u8> = Vec::new();

    for header_name in parts.headers.unwrap_or("date").split(' ') {
        if header_name == "(request-target)" {
            write!(
                &mut to_verify,
                "(request-target): {} {}\n",
                request.method().as_str().to_ascii_lowercase(),
                request.uri()
            )?;
        } else if let Some(header_value) = request.headers().get(header_name) {
            write!(
                &mut to_verify,
                "{}: {}\n",
                header_name,
                header_value.to_str()?
            )?;
        } else {
            return Ok(false);
        }
    }

    // `pop` to remove the trailing newline. If it returns `None`, there were no headers, so we
    // should default to checking the `date` header.
    if to_verify.pop().is_none() {
        if let Some(date) = request.headers().get("date") {
            write!(&mut to_verify, "date: {}", date.to_str()?)?;
        } else {
            return Ok(false);
        }
    }

    verifier.update(&to_verify)?;

    Ok(verifier.verify(&signature)?)
}

#[derive(Debug)]
pub struct SignatureParts<'a> {
    pub headers: Option<&'a str>,
    pub key_id: &'a str,
    pub signature: &'a str,
    pub algorithm: Option<&'a str>,
}

pub fn parse_signature_parts<'a>(signature_string: &'a str) -> Option<SignatureParts<'a>> {
    let mut headers = None;
    let mut key_id = None;
    let mut algorithm = None;
    let mut signature = None;

    for part in signature_string.split(',') {
        let mut kv = part.splitn(2, '=');

        if let (Some(key), Some(value)) = (kv.next(), kv.next()) {
            if !(value.starts_with('"') && value.ends_with('"')) {
                return None;
            }

            let value = value.trim_start_matches('"').trim_end_matches('"');

            match key {
                "headers" => headers = Some(value),
                "keyId" => key_id = Some(value),
                "algorithm" => algorithm = Some(value),
                "signature" => signature = Some(value),
                _ => {}
            }
        } else {
            return None;
        }
    }

    if let (Some(k), Some(s)) = (key_id, signature) {
        return Some(SignatureParts {
            key_id: k,
            signature: s,
            headers,
            algorithm,
        });
    } else {
        return None;
    }
}

pub fn add_signature_header<T>(
    request: &mut http::Request<T>,
    key_id: &str,
    digest: MessageDigest,
    private_key: &PKeyRef<impl HasPrivate>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    request.headers_mut().remove("signature");

    let header = create_signature_header(&request, key_id, digest, private_key)?;
    request.headers_mut().insert("signature", header.parse()?);
    Ok(())
}

// Assumes request doesn't already have a signature header
pub fn create_signature_header<T>(
    request: &http::Request<T>,
    key_id: &str,
    digest: MessageDigest,
    private_key: &PKeyRef<impl HasPrivate>,
) -> Result<String, Box<dyn Error + Send + Sync>> {
    let signature = compute_signature(&request, digest, &private_key)?;
    let base64_signature = base64::encode(&signature);

    let mut output = String::new();

    write!(
        &mut output,
        "keyId=\"{}\",headers=\"(request-target)",
        key_id
    )?;
    for (header_name, _) in request.headers() {
        write!(&mut output, " {}", header_name.as_str())?;
    }

    write!(&mut output, "\",signature=\"{}\"", base64_signature)?;

    Ok(output)
}

pub fn compute_signature<T>(
    request: &http::Request<T>,
    digest: MessageDigest,
    private_key: &PKeyRef<impl HasPrivate>,
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let mut signer = Signer::new(digest, private_key)?;

    let mut payload_to_sign: Vec<u8> = Vec::new();
    write!(
        &mut payload_to_sign,
        "(request-target): {} {}",
        request.method().as_str().to_ascii_lowercase(),
        request.uri()
    )?;

    for (header_name, header_value) in request.headers() {
        // HeaderName's `as_str` is guaranteed to be lowercase
        write!(
            &mut payload_to_sign,
            "\n{}: {}",
            header_name.as_str(),
            header_value.to_str()?
        )?;
    }

    signer.update(&payload_to_sign)?;
    Ok(signer.sign_to_vec()?)
}
