//! Client authentication library for MOZAIK
//!
//! Uses OAuth 2.0 RFC 6749, section 4.4 Client Credentials Flow
//!
//! Provides [AuthToken]. This struct does all the bookkeeping to request Bearer tokens.
//!
//! ## Usage
//! ```rust
//! use client_auth::AuthToken;
//!
//! // You can use environment variables or hardcode these
//! let client_id = env::var("CLIENT_ID").unwrap();
//! let client_secret = env::var("CLIENT_SECRET").unwrap();
//! let auth_endpoint = env::var("AUTH_ENDPOINT").unwrap();
//! let token_endpoint = env::var("TOKEN_ENDPOINT").unwrap();
//!
//! // Create AuthToken instance
//! let mut auth_token = AuthToken::new(
//!     client_id.clone(),
//!     client_secret,
//!     auth_endpoint,
//!     token_endpoint,
//! )
//! .await;
//!
//!
//! // When you need the token
//! let token = auth_token.token().await;
//! ```

use std::time::{Duration, SystemTime};

use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AccessToken, AuthUrl, ClientId, ClientSecret,
    TokenResponse, TokenUrl,
};

pub struct AuthToken {
    client: BasicClient,
    token: AccessToken,
    issued_at: SystemTime,
    expires_in: Duration,
}

impl AuthToken {
    pub async fn new(
        client_id: String,
        client_secret: String,
        auth_endpoint: String,
        token_endpoint: String,
    ) -> Self {
        let token_client = BasicClient::new(
            ClientId::new(client_id),
            Some(ClientSecret::new(client_secret)),
            AuthUrl::new(auth_endpoint).unwrap(),
            Some(TokenUrl::new(token_endpoint).unwrap()),
        );

        let token_response = token_client
            .exchange_client_credentials()
            .request_async(async_http_client)
            .await
            .unwrap();

        AuthToken {
            client: token_client,
            token: token_response.access_token().to_owned(),
            issued_at: SystemTime::now(),
            expires_in: token_response
                .expires_in()
                .unwrap_or(Duration::from_secs(300)),
        }
    }

    pub async fn token(&mut self) -> String {
        // Request new token if old token is only valid for 15 seconds
        if self.issued_at.elapsed().unwrap().as_secs() >= self.expires_in.as_secs() - 15 {
            let token_response = self
                .client
                .exchange_client_credentials()
                .request_async(async_http_client)
                .await
                .unwrap();

            self.token = token_response.access_token().to_owned();
            self.issued_at = SystemTime::now();
            self.expires_in = token_response
                .expires_in()
                .unwrap_or(Duration::from_secs(300));
        }

        self.token.secret().to_owned()
    }
}
