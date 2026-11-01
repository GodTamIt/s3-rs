use std::time::Duration;

use http::{HeaderMap, Method};
use secrecy::ExposeSecret;
use time::OffsetDateTime;

use super::S3Client;
use crate::error::{ErrorCategory, RetryClassification, S3Error};
use crate::operation::{
    ObjectKey, PartNumber, PresignPutRequest, PresignedRequest, PresignedUrl, UploadId,
};
use crate::signing::{
    Header, PresigningRequest, QueryParam, SigningCredentials, SigningPath, SigningScope,
    sign_presigned,
};

impl S3Client {
    /// Generates a presigned GET URL whose standard formatting is redacted.
    pub async fn presigned_get(
        &self,
        key: &ObjectKey,
        expires: Duration,
    ) -> Result<PresignedUrl, S3Error> {
        self.presign("GET", key, &[], expires).await
    }

    /// Generates a presigned PUT URL bound to the request's headers.
    ///
    /// The returned [`PresignedRequest`] lists the caller-supplied headers whose
    /// values were signed. Send those headers unchanged; SigV4 applies standard
    /// header normalization when signing. `host` is signed from the URL's
    /// authority and is never part of [`PresignedRequest::headers`], so a
    /// request without additional headers yields a host-only signature.
    ///
    /// Signing-owned names (`host`, `authorization`, `x-amz-date`,
    /// `x-amz-security-token`, `x-amz-content-sha256`) and hop-by-hop or
    /// framing names (`connection`, `keep-alive`, `proxy-authenticate`,
    /// `proxy-authorization`, `te`, `trailer`, `transfer-encoding`, `upgrade`)
    /// are rejected. `content-length` is the one exception: when present it
    /// must be a single nonempty decimal value, and that value is the exact
    /// upload length rather than a maximum. Note that browsers cannot
    /// explicitly set `content-length`.
    ///
    /// The payload is signed as `UNSIGNED-PAYLOAD`: the signature does not bind
    /// a body digest, and a signed `content-type` does not validate the body
    /// bytes. The service may still validate a supplied checksum header.
    ///
    /// [`PresignedRequest`]'s `Debug` and error messages omit header values;
    /// callers can access them through [`PresignedRequest::headers`].
    pub async fn presigned_put(
        &self,
        request: PresignPutRequest,
    ) -> Result<PresignedRequest, S3Error> {
        let PresignPutRequest {
            key,
            expires,
            headers,
        } = request;
        let url = self
            .presign_with_headers("PUT", &key, &[], expires, &headers)
            .await?;
        Ok(PresignedRequest::new(Method::PUT, url, headers))
    }

    /// Generates a presigned HEAD URL whose standard formatting is redacted.
    pub async fn presigned_head(
        &self,
        key: &ObjectKey,
        expires: Duration,
    ) -> Result<PresignedUrl, S3Error> {
        self.presign("HEAD", key, &[], expires).await
    }

    /// Generates a presigned DELETE URL whose standard formatting is redacted.
    pub async fn presigned_delete(
        &self,
        key: &ObjectKey,
        expires: Duration,
    ) -> Result<PresignedUrl, S3Error> {
        self.presign("DELETE", key, &[], expires).await
    }

    /// Generates a presigned request that initiates a multipart upload.
    pub async fn presigned_create_multipart_upload(
        &self,
        key: &ObjectKey,
        expires: Duration,
    ) -> Result<PresignedUrl, S3Error> {
        self.presign("POST", key, &[("uploads", "")], expires).await
    }

    /// Generates a presigned multipart part-upload URL.
    pub async fn presigned_upload_part(
        &self,
        key: &ObjectKey,
        upload_id: &UploadId,
        part_number: PartNumber,
        expires: Duration,
    ) -> Result<PresignedUrl, S3Error> {
        let part_number = part_number.get().to_string();
        self.presign(
            "PUT",
            key,
            &[
                ("partNumber", part_number.as_str()),
                ("uploadId", upload_id.as_str()),
            ],
            expires,
        )
        .await
    }

    /// Generates a presigned multipart abort URL.
    pub async fn presigned_abort_multipart_upload(
        &self,
        key: &ObjectKey,
        upload_id: &UploadId,
        expires: Duration,
    ) -> Result<PresignedUrl, S3Error> {
        self.presign("DELETE", key, &[("uploadId", upload_id.as_str())], expires)
            .await
    }

    async fn presign(
        &self,
        method: &'static str,
        key: &ObjectKey,
        query: &[(&str, &str)],
        expires: Duration,
    ) -> Result<PresignedUrl, S3Error> {
        self.presign_with_headers(method, key, query, expires, &HeaderMap::new())
            .await
    }

    async fn presign_with_headers(
        &self,
        method: &'static str,
        key: &ObjectKey,
        query: &[(&str, &str)],
        expires: Duration,
        caller_headers: &HeaderMap,
    ) -> Result<PresignedUrl, S3Error> {
        let target = self.operation_target(Some(key.as_str()))?;
        let headers = presign_headers(caller_headers, target.authority())?;
        let credentials = self
            .inner
            .config
            .credentials_provider()
            .provide_credentials()
            .await?;
        let now = OffsetDateTime::now_utc();
        if credentials.expires_by(now) {
            return Err(S3Error::new(
                ErrorCategory::Authentication,
                "credential provider returned expired credentials",
                RetryClassification::Never,
            ));
        }
        let expires_at = time::Duration::try_from(expires)
            .ok()
            .and_then(|duration| now.checked_add(duration));
        if credentials.expires_at().is_some_and(|credential_expiry| {
            expires_at.is_none_or(|url_expiry| url_expiry >= credential_expiry)
        }) {
            return Err(S3Error::new(
                ErrorCategory::Authentication,
                "presigned URL lifetime must end before the credentials expire",
                RetryClassification::Never,
            ));
        }
        let secret = credentials.secret_access_key().expose_secret();
        let session_token = credentials.session_token().map(ExposeSecret::expose_secret);
        let signing_credentials = SigningCredentials::new(
            credentials.access_key_id(),
            secret.as_bytes(),
            session_token,
        );
        let query = query
            .iter()
            .map(|(name, value)| QueryParam::new(name, value))
            .collect::<Vec<_>>();
        let signing_request = PresigningRequest {
            method,
            uri_path: SigningPath::encoded(target.path_and_query()),
            query: &query,
            headers: &headers,
            expires,
            payload_hash: None,
        };
        let query: crate::signing::PresignedQuery = sign_presigned(
            &signing_credentials,
            SigningScope::new(self.inner.config.region(), "s3"),
            &signing_request,
            now,
        )
        .map_err(|error| {
            S3Error::new(
                ErrorCategory::Authentication,
                "presigned URL generation failed",
                RetryClassification::Never,
            )
            .with_source(error)
        })?;
        Ok(PresignedUrl::new(format!(
            "{}?{}",
            target.as_str(),
            query.as_str()
        )))
    }
}

const PRESIGN_RESERVED_HEADERS: [&str; 13] = [
    "host",
    "authorization",
    "x-amz-date",
    "x-amz-security-token",
    "x-amz-content-sha256",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

fn presign_headers<'a>(
    headers: &'a HeaderMap,
    authority: &'a str,
) -> Result<Vec<Header<'a>>, S3Error> {
    for name in PRESIGN_RESERVED_HEADERS {
        if headers.contains_key(name) {
            return Err(header_collision(name));
        }
    }
    let content_lengths = headers.get_all("content-length");
    let mut lengths = content_lengths.iter();
    let valid_length = match (lengths.next(), lengths.next()) {
        (None, None) => true,
        (Some(value), None) => value.to_str().ok().is_some_and(|text| {
            !text.is_empty()
                && text.bytes().all(|byte| byte.is_ascii_digit())
                && text.parse::<u64>().is_ok()
        }),
        _ => false,
    };
    if !valid_length {
        return Err(S3Error::configuration(
            "presigned content-length must be a single nonempty decimal value",
        ));
    }
    let mut signed_headers = Vec::with_capacity(headers.len() + 1);
    signed_headers.push(Header::new("host", authority));
    for (name, value) in headers {
        let value = value
            .to_str()
            .map_err(|_| S3Error::configuration("request contains an invalid header value"))?;
        signed_headers.push(Header::new(name.as_str(), value));
    }
    Ok(signed_headers)
}

fn header_collision(name: &str) -> S3Error {
    S3Error::configuration(format!(
        "request header `{name}` conflicts with a generated, signing-owned, or transport-owned header"
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use http::HeaderValue;

    use super::*;
    use crate::config::S3Config;
    use crate::credentials::{Credentials, StaticCredentialsProvider};

    fn test_client() -> S3Client {
        let credentials = Credentials::new("access", "secret", None).unwrap();
        let config = S3Config::builder()
            .bucket("bucket")
            .credentials_provider(Arc::new(StaticCredentialsProvider::new(credentials)))
            .build()
            .unwrap();
        S3Client::new(config).unwrap()
    }

    #[tokio::test]
    async fn presigned_put_binds_signed_headers() {
        let client = test_client();
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("text/plain"));
        headers.insert("content-length", HeaderValue::from_static("7"));
        headers.append("x-amz-meta-tag", HeaderValue::from_static("one"));
        headers.append("x-amz-meta-tag", HeaderValue::from_static("two"));

        let request = client
            .presigned_put(
                PresignPutRequest::new(ObjectKey::new("key").unwrap(), Duration::from_secs(60))
                    .with_headers(headers),
            )
            .await
            .unwrap();

        assert_eq!(request.method(), Method::PUT);
        assert_eq!(request.headers()["content-type"], "text/plain");
        assert_eq!(request.headers()["content-length"], "7");
        assert_eq!(
            request.headers().get_all("x-amz-meta-tag").iter().count(),
            2
        );
        assert!(!request.headers().contains_key("host"));
        let url = request.url().expose();
        assert!(
            url.contains(
                "X-Amz-SignedHeaders=content-length%3Bcontent-type%3Bhost%3Bx-amz-meta-tag"
            )
        );
    }

    #[tokio::test]
    async fn presigned_put_debug_is_redacted() {
        let client = test_client();
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("text/plain"));
        headers.insert("x-amz-meta-tag", HeaderValue::from_static("sentinel-value"));

        let input = PresignPutRequest::new(ObjectKey::new("key").unwrap(), Duration::from_secs(60))
            .with_headers(headers);
        let input_debug = format!("{input:?}");
        assert!(!input_debug.contains("text/plain"));
        assert!(!input_debug.contains("sentinel-value"));

        let request = client.presigned_put(input).await.unwrap();

        let debug = format!("{request:?}");
        assert!(debug.contains("PresignedRequest"));
        assert!(!debug.contains("text/plain"));
        assert!(!debug.contains("sentinel-value"));
        assert!(!debug.contains("X-Amz-Signature"));
    }

    #[tokio::test]
    async fn presigned_put_rejects_reserved_and_invalid_headers() {
        let client = test_client();

        for name in PRESIGN_RESERVED_HEADERS {
            let mut headers = HeaderMap::new();
            headers.insert(name, HeaderValue::from_static("sentinel-value"));
            let error = client
                .presigned_put(
                    PresignPutRequest::new(ObjectKey::new("key").unwrap(), Duration::from_secs(60))
                        .with_headers(headers),
                )
                .await
                .unwrap_err();
            assert!(error.message().contains(name));
            assert!(!error.message().contains("sentinel-value"));
        }

        for value in ["", " 5", "+5", "1 2", "12.0", "99999999999999999999999"] {
            let mut headers = HeaderMap::new();
            headers.insert("content-length", HeaderValue::try_from(value).unwrap());
            let error = client
                .presigned_put(
                    PresignPutRequest::new(ObjectKey::new("key").unwrap(), Duration::from_secs(60))
                        .with_headers(headers),
                )
                .await
                .unwrap_err();
            assert_eq!(
                error.message(),
                "presigned content-length must be a single nonempty decimal value"
            );
        }

        let mut headers = HeaderMap::new();
        headers.append("content-length", HeaderValue::from_static("1"));
        headers.append("content-length", HeaderValue::from_static("2"));
        let error = client
            .presigned_put(
                PresignPutRequest::new(ObjectKey::new("key").unwrap(), Duration::from_secs(60))
                    .with_headers(headers),
            )
            .await
            .unwrap_err();
        assert_eq!(
            error.message(),
            "presigned content-length must be a single nonempty decimal value"
        );

        let mut headers = HeaderMap::new();
        headers.insert("x-amz-meta-tag", HeaderValue::from_bytes(&[0xFF]).unwrap());
        let error = client
            .presigned_put(
                PresignPutRequest::new(ObjectKey::new("key").unwrap(), Duration::from_secs(60))
                    .with_headers(headers),
            )
            .await
            .unwrap_err();
        assert_eq!(error.message(), "request contains an invalid header value");

        let mut headers = HeaderMap::new();
        headers.insert("content-length", HeaderValue::from_static("0"));
        let request = client
            .presigned_put(
                PresignPutRequest::new(ObjectKey::new("key").unwrap(), Duration::from_secs(60))
                    .with_headers(headers),
            )
            .await
            .unwrap();
        assert!(
            request
                .url()
                .expose()
                .contains("X-Amz-SignedHeaders=content-length%3Bhost")
        );
    }

    #[tokio::test]
    async fn presigned_put_remains_host_only() {
        let client = test_client();
        let request = client
            .presigned_put(PresignPutRequest::new(
                ObjectKey::new("key").unwrap(),
                Duration::from_secs(60),
            ))
            .await
            .unwrap();
        assert!(request.url().expose().contains("X-Amz-SignedHeaders=host"));
    }

    #[tokio::test]
    async fn presigned_output_requires_explicit_exposure() {
        let credentials = Credentials::new("access", "secret", None).unwrap();
        let config = S3Config::builder()
            .bucket("bucket")
            .credentials_provider(Arc::new(StaticCredentialsProvider::new(credentials)))
            .build()
            .unwrap();
        let client = S3Client::new(config).unwrap();
        let url = client
            .presigned_get(&ObjectKey::new("a/../b").unwrap(), Duration::from_secs(60))
            .await
            .unwrap();
        assert!(!format!("{url:?}").contains("X-Amz-Signature"));
        assert!(url.expose().contains("/bucket/a/../b?"));
        assert!(url.expose().contains("X-Amz-Signature="));

        let upload_id = UploadId::new("opaque/upload+id").unwrap();
        let multipart = client
            .presigned_upload_part(
                &ObjectKey::new("multipart").unwrap(),
                &upload_id,
                PartNumber::new(7).unwrap(),
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        assert!(multipart.expose().contains("partNumber=7"));
        assert!(multipart.expose().contains("uploadId=opaque%2Fupload%2Bid"));
        assert!(multipart.expose().contains("X-Amz-Signature="));
    }

    #[tokio::test]
    async fn presigned_url_must_expire_before_session_credentials() {
        let credentials = Credentials::with_expiration(
            "access",
            "secret",
            Some("session".to_owned()),
            Some(OffsetDateTime::now_utc() + time::Duration::minutes(5)),
        )
        .unwrap();
        let config = S3Config::builder()
            .bucket("bucket")
            .credentials_provider(Arc::new(StaticCredentialsProvider::new(credentials)))
            .build()
            .unwrap();
        let client = S3Client::new(config).unwrap();

        let error = client
            .presigned_get(&ObjectKey::new("key").unwrap(), Duration::from_secs(5 * 60))
            .await
            .expect_err("URL outliving credentials is rejected");

        assert_eq!(error.category(), ErrorCategory::Authentication);
    }
}
