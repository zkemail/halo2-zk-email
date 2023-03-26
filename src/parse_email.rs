use futures::executor::block_on;
use mail_auth::common::verify::VerifySignature;
use mail_auth::Error;
use mail_auth::{AuthenticatedMessage, DkimResult, Resolver};
use sha2::{self, Digest, Sha256};

pub async fn parse_external_eml(raw_email: &String) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Error> {
    let resolver = Resolver::new_cloudflare_tls().unwrap();
    let authenticated_message = AuthenticatedMessage::parse(raw_email.as_bytes()).unwrap();

    // Validate signature
    let result = resolver.verify_dkim(&authenticated_message).await;
    assert!(result.iter().all(|s| s.result() == &DkimResult::Pass));
    println!("Result: {:?}", result[0]);

    // Extract the parsed + canonicalized headers along with the signed value for them
    let (parsed_headers, signed_parsed_headers) = authenticated_message.get_canonicalized_header().unwrap();

    let signature = result[0].signature().unwrap();
    println!("B: {:?}", std::str::from_utf8(signature.signature()));
    println!(
        "Parsed headers: {:?} {:?}",
        std::str::from_utf8(parsed_headers.as_slice()),
        std::str::from_utf8(signed_parsed_headers)
    );

    let body_bytes = &authenticated_message.raw_message[authenticated_message.body_offset..];
    let hash = Sha256::digest(&body_bytes);
    #[warn(deprecated)]
    assert_eq!(
        base64::encode(hash),
        base64::encode(signature.body_hash()),
        "Extracted body hash and calculated body hash do not match!"
    );

    // Convert body_bytes to a vector
    let body_bytes_vec = body_bytes.to_vec();
    Ok((parsed_headers.clone(), body_bytes.to_vec().clone(), signature.clone().signature().to_vec().clone()))
    // signature.clone().signature()))
}
