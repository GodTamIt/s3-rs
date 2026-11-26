use std::time::Duration;

use http::header::CONTENT_LENGTH;
use http::{HeaderMap, Method};
use secrecy::ExposeSecret;
use time::OffsetDateTime;

use super::S3Client;
use super::request::reject_owned_headers;
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

    /// Generates a presigned PUT request bound to the request's headers.
    ///
    /// The uploader must send [`PresignedRequest::headers`] unchanged with the
    /// URL. Signing- and transport-owned headers are rejected, except that a
    /// single decimal `content-length` may be signed; it binds the exact upload
    /// size, not a maximum, and browsers cannot set it explicitly. The body is
    /// signed as `UNSIGNED-PAYLOAD`, so a signed `content-type` does not
    /// validate the body bytes.
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

fn presign_headers<'a>(
    headers: &'a HeaderMap,
    authority: &'a str,
) -> Result<Vec<Header<'a>>, S3Error> {
    reject_owned_headers(headers)?;
    let mut lengths = headers.get_all(CONTENT_LENGTH).iter();
    if let Some(length) = lengths.next()
        && (lengths.next().is_some()
            // `u64::from_str` alone would accept a leading `+`.
            || !length.to_str().is_ok_and(|text| {
                text.bytes().all(|byte| byte.is_ascii_digit()) && text.parse::<u64>().is_ok()
            }))
    {
        return Err(S3Error::configuration(
            "presigned content-length must be a single decimal value",
        ));
    }
    std::iter::once(Ok(Header::new("host", authority)))
        .chain(headers.iter().map(|(name, value)| {
            value
                .to_str()
                .map(|value| Header::new(name.as_str(), value))
                .map_err(|_| S3Error::configuration("request contains an invalid header value"))
        }))
        .collect()
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

    async fn presign_put(headers: HeaderMap) -> Result<PresignedRequest, S3Error> {
        test_client()
            .presigned_put(
                PresignPutRequest::new(ObjectKey::new("key").unwrap(), Duration::from_secs(60))
                    .with_headers(headers),
            )
            .await
    }

    fn signed_headers(request: &PresignedRequest) -> &str {
        let url = request.url().expose();
        let start = url.find("X-Amz-SignedHeaders=").unwrap();
        url[start..].split('&').next().unwrap()
    }

    #[tokio::test]
    async fn presigned_put_binds_signed_headers() {
        let request = presign_put(HeaderMap::new()).await.unwrap();
        assert_eq!(signed_headers(&request), "X-Amz-SignedHeaders=host");

        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("text/plain"));
        headers.insert("content-length", HeaderValue::from_static("0"));
        headers.append("x-amz-meta-tag", HeaderValue::from_static("one"));
        headers.append("x-amz-meta-tag", HeaderValue::from_static("two"));
        let request = presign_put(headers.clone()).await.unwrap();

        assert_eq!(request.method(), Method::PUT);
        assert_eq!(request.headers(), &headers);
        assert_eq!(
            signed_headers(&request),
            "X-Amz-SignedHeaders=content-length%3Bcontent-type%3Bhost%3Bx-amz-meta-tag"
        );
    }

    #[tokio::test]
    async fn presigned_put_debug_is_redacted() {
        let mut headers = HeaderMap::new();
        headers.insert("x-amz-meta-tag", HeaderValue::from_static("sentinel-value"));
        let input = PresignPutRequest::new(ObjectKey::new("key").unwrap(), Duration::from_secs(60))
            .with_headers(headers.clone());
        assert!(!format!("{input:?}").contains("sentinel-value"));

        let debug = format!("{:?}", presign_put(headers).await.unwrap());
        assert!(!debug.contains("sentinel-value"));
        assert!(!debug.contains("X-Amz-Signature"));
    }

    #[tokio::test]
    async fn presigned_put_rejects_owned_and_invalid_headers() {
        for name in ["host", "x-amz-date", "transfer-encoding"] {
            let mut headers = HeaderMap::new();
            headers.insert(name, HeaderValue::from_static("sentinel-value"));
            let error = presign_put(headers).await.unwrap_err();
            assert!(error.message().contains(name));
            assert!(!error.message().contains("sentinel-value"));
        }

        let mut invalid_lengths = ["", " 5", "+5", "12.0", "99999999999999999999999"]
            .map(|value| {
                let mut headers = HeaderMap::new();
                headers.insert("content-length", HeaderValue::try_from(value).unwrap());
                headers
            })
            .to_vec();
        let mut repeated = HeaderMap::new();
        repeated.append("content-length", HeaderValue::from_static("1"));
        repeated.append("content-length", HeaderValue::from_static("1"));
        invalid_lengths.push(repeated);
        for headers in invalid_lengths {
            let error = presign_put(headers).await.unwrap_err();
            assert_eq!(
                error.message(),
                "presigned content-length must be a single decimal value"
            );
        }

        let mut headers = HeaderMap::new();
        headers.insert("x-amz-meta-tag", HeaderValue::from_bytes(&[0xFF]).unwrap());
        let error = presign_put(headers).await.unwrap_err();
        assert_eq!(error.message(), "request contains an invalid header value");
    }

    #[tokio::test]
    async fn presigned_output_requires_explicit_exposure() {
        let client = test_client();
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
