use cfdkim::*;
use futures::executor::block_on;
use mail_auth::common::verify::VerifySignature;
use mail_auth::Error;
use mail_auth::{AuthenticatedMessage, DkimResult, Resolver};
use sha2::{self, Digest, Sha256};
use std::env;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::proto::rr::{RData, RecordType};
use trust_dns_resolver::AsyncResolver;

pub async fn parse_external_eml(raw_email: &String) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), Error> {
    let resolver = Resolver::new_cloudflare_tls().unwrap();
    let authenticated_message = AuthenticatedMessage::parse(raw_email.as_bytes()).unwrap();

    // Validate signature
    let result = resolver.verify_dkim(&authenticated_message).await;
    assert!(result.iter().all(|s| s.result() == &DkimResult::Pass));
    println!("Result: {:?}", result[0]);

    // Extract the parsed + canonicalized headers along with the signed value for them
    let (parsed_headers, signed_parsed_headers) = authenticated_message.get_canonicalized_header().unwrap();
    let signature = result[0].signature().unwrap();

    let body_bytes = &authenticated_message.raw_message[authenticated_message.body_offset..];
    let hash = Sha256::digest(&body_bytes);
    #[warn(deprecated)]
    assert_eq!(
        base64::encode(hash),
        base64::encode(signature.body_hash()),
        "Extracted body hash and calculated body hash do not match!"
    );

    // Get DNS TXT record
    let dkim_domain = signature.domain_key();
    println!("Domain: {dkim_domain:?}");
    let key = get_public_key(dkim_domain.as_str()).await;
    println!("Public key of domain {key:?}");
    // Convert String key to [u8]
    let unwrapped_key = key.unwrap();
    let key_bytes = unwrapped_key.as_bytes();
    // let dkim_public_key = cfdkim::lookup_dkim_public_key(key).unwrap();
    // let rsa_public_key = dkim_public_key.rsa_public_key();

    // Convert body_bytes to a vector
    let body_bytes_vec = body_bytes.to_vec();
    Ok((
        parsed_headers.clone(),
        body_bytes.to_vec().clone(),
        key_bytes.to_vec().clone(),
        signature.clone().signature().to_vec().clone(),
    ))
    // signature.clone().signature()))
}

async fn get_public_key(domain: &str) -> Result<String, Box<dyn std::error::Error>> {
    let resolver = AsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())?;
    let response = resolver.lookup(domain, RecordType::TXT).await?;
    println!("Response: {:?}", response);
    for record in response.iter() {
        if let RData::TXT(ref txt) = *record {
            let txt_data = txt.txt_data();
            // Format txt data to convert from u8 to string
            let data_bytes: Vec<u8> = txt_data.iter().flat_map(|b| b.as_ref()).cloned().collect();
            let data = String::from_utf8_lossy(&data_bytes);
            println!("Data: {:?}", data);

            if data.contains("k=rsa;") {
                let parts: Vec<_> = data.split("; ").collect();
                for part in parts {
                    if part.starts_with("p=") {
                        assert_eq!(part.strip_prefix("p=").unwrap(), part[2..].to_string());
                        return Ok(part.strip_prefix("p=").unwrap().to_string());
                    }
                }
            }
        }
    }

    Err("RSA public key not found.".into())
}

#[tokio::main]
async fn main() {
    let domain = "20210112._domainkey.gmail.com.";
    match get_public_key(domain).await {
        Ok(key) => println!("RSA public key: {}", key),
        Err(e) => eprintln!("Error: {}", e),
    }
}
