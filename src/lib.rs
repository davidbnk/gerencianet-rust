use base64::{engine::general_purpose, Engine};
use chrono::{DateTime, Utc};
use rand::{thread_rng, Rng};
use reqwest::header;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::error::Error;
use std::fmt::Display;
use tokio::sync::Mutex;

#[derive(Debug)]
pub struct GerencianetToken {
    access_token: String,
    expiration: DateTime<Utc>,
}

#[derive(Debug)]
pub struct Gerencianet {
    url: String,
    client_id: String,
    client_secret: String,
    pix_key: String,
    client: reqwest::Client,
    token_mutex: Mutex<Option<GerencianetToken>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Pagador {
    pub cnpj: String,
    pub nome: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Horario {
    pub solicitacao: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Devolucoes {
    pub id: String,
    pub rtr_id: String,
    pub valor: String,
    pub horario: Horario,
    pub status: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Pix {
    pub txid: String,
    pub valor: String,
    pub horario: String,
    pub end_to_end_id: Option<String>,
    pub pagador: Option<Pagador>,
    pub info_pagador: Option<String>,
    pub devolucoes: Option<Vec<Devolucoes>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Calendario {
    pub criacao: String,
    pub expiracao: i64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Devedor {
    pub cnpj: String,
    pub nome: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Valor {
    pub original: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Location {
    pub id: i64,
    pub location: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Cobranca {
    pub status: String,
    pub calendario: Calendario,
    pub location: String,
    pub loc: Option<Location>,
    pub txid: String,
    pub revisao: i32,
    pub devedor: Option<Devedor>,
    pub valor: Valor,
    pub chave: String,
    pub solicitacao_pagador: Option<String>,
    pub pix: Option<Vec<Pix>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct QRCode {
    #[serde(rename = "imagemQrcode")]
    pub imagem_qrcode: String,
    pub qrcode: String,
}

#[derive(Debug)]
pub enum GerencianetError {
    RequestError(reqwest::Error),
    ContractError(String),
    ResponseError(GerencianetResponseError),
    ResponseParseError(String),
}

impl Display for GerencianetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RequestError(e) => write!(f, "GerencianetError::RequestError: {}", e),
            Self::ContractError(e) => write!(f, "GerencianetError::ContractError: {}", e),
            Self::ResponseError(e) => write!(f, "GerencianetError::ResponseError: {}", e.mensagem),
            Self::ResponseParseError(e) => write!(f, "GerencianetError::ResponseParseError: {}", e),
        }
    }
}

impl Error for GerencianetError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::RequestError(e) => Some(e),
            _ => None,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GerencianetResponseError {
    pub nome: String,
    pub mensagem: String,
}

impl From<reqwest::Error> for GerencianetError {
    fn from(e: reqwest::Error) -> Self {
        Self::RequestError(e)
    }
}

impl Gerencianet {
    pub fn new(
        client_id: String,
        client_secret: String,
        url: String,
        pix_key: String,
        p12_cert_base64: String,
        cert_password: String,
    ) -> Self {
        let der = general_purpose::STANDARD
            .decode(p12_cert_base64)
            .expect("Failed decoding p12_cert_base64 from base64");

        let pkcs12 = reqwest::Identity::from_pkcs12_der(&der, &cert_password)
            .expect("Failed parsing pkcs12 certificate");
        let auth = general_purpose::STANDARD.encode(format!("{client_id}:{client_secret}"));
        let mut headers = header::HeaderMap::new();
        headers.insert(
            "Authorization",
            format!("Basic {auth}")
                .parse()
                .expect("Failed parsing auth header"),
        );

        let client = reqwest::Client::builder()
            .identity(pkcs12)
            .default_headers(headers)
            .build()
            .expect("Failed building client");
        Self {
            url,
            client_id,
            client_secret,
            pix_key,
            client,
            token_mutex: Mutex::new(None),
        }
    }

    async fn get_access_token(&self) -> Result<String, GerencianetError> {
        let mut token = self.token_mutex.lock().await;
        if let Some(t) = token.as_ref() {
            if t.expiration > Utc::now() {
                return Ok(t.access_token.to_owned());
            }
        }
        let auth =
            general_purpose::STANDARD.encode(format!("{}:{}", self.client_id, self.client_secret));
        let result = self
            .client
            .post(format!("{0}/oauth/token", self.url))
            .header("Authorization", format!("Basic {auth}"))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body("grant_type=client_credentials")
            .send()
            .await;
        #[derive(Deserialize)]
        struct Response {
            access_token: String,
            expires_in: i64,
        }
        let response: Response = result?.json().await?;
        *token = Some(GerencianetToken {
            access_token: response.access_token.to_owned(),
            expiration: Utc::now() + chrono::Duration::seconds(response.expires_in + 60),
        });
        Ok(response.access_token)
    }

    pub async fn list_charges(
        &self,
        since: chrono::DateTime<Utc>,
    ) -> Result<Vec<Cobranca>, GerencianetError> {
        let access_token = self.get_access_token().await?;
        let mut params = HashMap::new();
        params.insert("inicio", since.to_rfc3339());
        params.insert("fim", Utc::now().to_rfc3339());

        let result = self
            .client
            .get(format!("{0}/v2/cob", self.url))
            .query(&params)
            .bearer_auth(access_token)
            .send()
            .await;
        #[derive(Debug, Deserialize, Serialize)]
        struct Response {
            cobs: Vec<Cobranca>,
        }
        let response: Response = result?.json().await?;
        Ok(response.cobs)
    }

    pub async fn get_charge(&self, txid: &str) -> Result<Option<Cobranca>, GerencianetError> {
        let access_token = self.get_access_token().await?;

        let response = self
            .client
            .get(format!("{0}/v2/cob/{txid}", self.url))
            .bearer_auth(access_token)
            .send()
            .await?;
        if response.status() == 404 || response.status() == 400 {
            return Ok(None);
        }

        let cob: Cobranca = response.json().await?;
        Ok(Some(cob))
    }

    pub async fn create_charge(
        &self,
        value: &str,
        txid: &str,
        expiration_seconds: i64,
    ) -> Result<Cobranca, GerencianetError> {
        assert!(txid.len() >= 26);
        assert!(txid.len() <= 35);
        let access_token = self.get_access_token().await?;
        let body = json!({
            "calendario": json!({
                "expiracao": expiration_seconds
            }),
            "valor": json!({
                "original": value,
            }),
            "chave": self.pix_key.clone(),
        });
        let response = self
            .client
            .put(format!("{0}/v2/cob/{txid}", self.url))
            .body(body.to_string())
            .bearer_auth(access_token)
            .send()
            .await?;
        if response.status() == 200 || response.status() == 201 {
            let cob: Cobranca = response.json().await?;
            return Ok(cob);
        } else if response.status() == 409 {
            return match self.get_charge(txid).await? {
                Some(cob) => Ok(cob),
                None => Err(GerencianetError::ContractError(
                    "Gerencianet returned 409 to indicate that \
                the charge already exists, but the charge could not be found"
                        .to_string(),
                )),
            };
        } else {
            let response_str = response.text().await?;
            match serde_json::from_str::<GerencianetResponseError>(&response_str) {
                Ok(err) => Err(GerencianetError::ResponseError(err)),
                Err(_) => Err(GerencianetError::ResponseParseError(response_str)),
            }
        }
    }

    pub async fn get_qr_code(&self, loc_id: i64) -> Result<Option<QRCode>, GerencianetError> {
        let access_token = self.get_access_token().await?;
        let response = self
            .client
            .get(format!("{0}/v2/loc/{loc_id}/qrcode", self.url))
            .bearer_auth(access_token)
            .send()
            .await?;
        if response.status() == 404 || response.status() == 400 {
            return Ok(None);
        }
        let qr_code: QRCode = response.json().await?;
        Ok(Some(qr_code))
    }

    pub async fn cancel_charge(&self, txid: &str) -> Result<Cobranca, GerencianetError> {
        let access_token = self.get_access_token().await?;
        let body = json!({
            "status": "REMOVIDA_PELO_USUARIO_RECEBEDOR",
        });
        let response = self
            .client
            .patch(format!("{0}/v2/cob/{txid}", self.url))
            .bearer_auth(access_token)
            .body(body.to_string())
            .send()
            .await?;
        if response.status() == 200 || response.status() == 201 {
            let cob: Cobranca = response.json().await?;
            Ok(cob)
        } else {
            let response_str = response.text().await?;
            match serde_json::from_str::<GerencianetResponseError>(&response_str) {
                Ok(err) => Err(GerencianetError::ResponseError(err)),
                Err(_) => Err(GerencianetError::ResponseParseError(response_str)),
            }
        }
    }

    pub async fn refund_charge(
        &self,
        end_to_end_id: &str,
        refund_id: &str,
        value: &str,
    ) -> Result<(), GerencianetError> {
        let access_token = self.get_access_token().await?;
        let body = json!({
            "valor": value,
        });
        let response = self
            .client
            .put(format!(
                "{0}/v2/pix/{end_to_end_id}/devolucao/{refund_id}",
                self.url
            ))
            .bearer_auth(access_token)
            .body(body.to_string())
            .send()
            .await?;
        if response.status() == 200 || response.status() == 201 {
            Ok(())
        } else {
            let response_str = response.text().await?;
            match serde_json::from_str::<GerencianetResponseError>(&response_str) {
                Ok(err) => Err(GerencianetError::ResponseError(err)),
                Err(_) => Err(GerencianetError::ResponseParseError(response_str)),
            }
        }
    }
}

#[allow(dead_code)]
fn random_string(length: usize) -> String {
    let mut rng = thread_rng();
    let alphabet: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let result: String = (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..alphabet.len());
            alphabet[idx] as char
        })
        .collect();
    result
}

#[tokio::test]
async fn test_refresh_token() {
    let client_id = std::env::var("GERENCIANET_CLIENT_ID")
        .expect("GERENCIANET_CLIENT_ID env variable is not set");
    let client_secret = std::env::var("GERENCIANET_CLIENT_SECRET")
        .expect("GERENCIANET_CLIENT_SECRET env variable is not set");
    let pix_key =
        std::env::var("GERENCIANET_PIX_KEY").expect("GERENCIANET_PIX_KEY env variable is not set");
    let url = std::env::var("GERENCIANET_URL").expect("GERENCIANET_URL env variable is not set");
    let der_base64 = std::env::var("GERENCIANET_KEY_BASE64")
        .expect("GERENCIANET_KEY_BASE64 env variable is not set");
    let der_password = std::env::var("GERENCIANET_KEY_PASSWORD")
        .expect("GERENCIANET_KEY_PASSWORD env variable is not set");
    let gn = Gerencianet::new(
        client_id,
        client_secret,
        url,
        pix_key,
        der_base64,
        der_password,
    );
    let result = gn.get_access_token().await;
    assert!(result.is_ok());
    assert!(!result.unwrap().is_empty());
}

#[tokio::test]
async fn test_list_charges() {
    let client_id = std::env::var("GERENCIANET_CLIENT_ID")
        .expect("GERENCIANET_CLIENT_ID env variable is not set");
    let client_secret = std::env::var("GERENCIANET_CLIENT_SECRET")
        .expect("GERENCIANET_CLIENT_SECRET env variable is not set");
    let pix_key =
        std::env::var("GERENCIANET_PIX_KEY").expect("GERENCIANET_PIX_KEY env variable is not set");
    let url = std::env::var("GERENCIANET_URL").expect("GERENCIANET_URL env variable is not set");
    let der_base64 = std::env::var("GERENCIANET_KEY_BASE64")
        .expect("GERENCIANET_KEY_BASE64 env variable is not set");
    let der_password = std::env::var("GERENCIANET_KEY_PASSWORD")
        .expect("GERENCIANET_KEY_PASSWORD env variable is not set");
    let gn = Gerencianet::new(
        client_id,
        client_secret,
        url,
        pix_key,
        der_base64,
        der_password,
    );
    let result = gn
        .list_charges(Utc::now() - chrono::Duration::days(365))
        .await;
    assert!(result.is_ok());
    assert!(!result.unwrap().is_empty());
}

#[tokio::test]
async fn test_get_charge_not_found() {
    let client_id = std::env::var("GERENCIANET_CLIENT_ID")
        .expect("GERENCIANET_CLIENT_ID env variable is not set");
    let client_secret = std::env::var("GERENCIANET_CLIENT_SECRET")
        .expect("GERENCIANET_CLIENT_SECRET env variable is not set");
    let pix_key =
        std::env::var("GERENCIANET_PIX_KEY").expect("GERENCIANET_PIX_KEY env variable is not set");
    let url = std::env::var("GERENCIANET_URL").expect("GERENCIANET_URL env variable is not set");
    let der_base64 = std::env::var("GERENCIANET_KEY_BASE64")
        .expect("GERENCIANET_KEY_BASE64 env variable is not set");
    let der_password = std::env::var("GERENCIANET_KEY_PASSWORD")
        .expect("GERENCIANET_KEY_PASSWORD env variable is not set");
    let gn = Gerencianet::new(
        client_id,
        client_secret,
        url,
        pix_key,
        der_base64,
        der_password,
    );
    let result = gn.get_charge("123").await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

#[tokio::test]
async fn test_get_charge_ok() {
    let client_id = std::env::var("GERENCIANET_CLIENT_ID")
        .expect("GERENCIANET_CLIENT_ID env variable is not set");
    let client_secret = std::env::var("GERENCIANET_CLIENT_SECRET")
        .expect("GERENCIANET_CLIENT_SECRET env variable is not set");
    let pix_key =
        std::env::var("GERENCIANET_PIX_KEY").expect("GERENCIANET_PIX_KEY env variable is not set");
    let url = std::env::var("GERENCIANET_URL").expect("GERENCIANET_URL env variable is not set");
    let der_base64 = std::env::var("GERENCIANET_KEY_BASE64")
        .expect("GERENCIANET_KEY_BASE64 env variable is not set");
    let der_password = std::env::var("GERENCIANET_KEY_PASSWORD")
        .expect("GERENCIANET_KEY_PASSWORD env variable is not set");
    let gn = Gerencianet::new(
        client_id,
        client_secret,
        url,
        pix_key,
        der_base64,
        der_password,
    );
    let charges = gn
        .list_charges(Utc::now() - chrono::Duration::days(365))
        .await
        .unwrap();
    let charge = charges.first().unwrap();
    let result = gn.get_charge(&charge.txid).await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_some());
}

#[tokio::test]
async fn test_create_charge() {
    let client_id = std::env::var("GERENCIANET_CLIENT_ID")
        .expect("GERENCIANET_CLIENT_ID env variable is not set");
    let client_secret = std::env::var("GERENCIANET_CLIENT_SECRET")
        .expect("GERENCIANET_CLIENT_SECRET env variable is not set");
    let pix_key =
        std::env::var("GERENCIANET_PIX_KEY").expect("GERENCIANET_PIX_KEY env variable is not set");
    let url = std::env::var("GERENCIANET_URL").expect("GERENCIANET_URL env variable is not set");
    let der_base64 = std::env::var("GERENCIANET_KEY_BASE64")
        .expect("GERENCIANET_KEY_BASE64 env variable is not set");
    let der_password = std::env::var("GERENCIANET_KEY_PASSWORD")
        .expect("GERENCIANET_KEY_PASSWORD env variable is not set");
    let gn = Gerencianet::new(
        client_id,
        client_secret,
        url,
        pix_key,
        der_base64,
        der_password,
    );
    let txid = random_string(30);
    let str_value = "1.23";
    let expiration_seconds = 3600;
    let charge = gn
        .create_charge(&str_value, &txid, expiration_seconds)
        .await
        .unwrap();
    assert_eq!(charge.txid, txid);
    assert_eq!(charge.valor.original, str_value);
    assert_eq!(charge.calendario.expiracao, expiration_seconds);

    let repeated_charge = gn
        .create_charge(&str_value, &txid, expiration_seconds)
        .await
        .unwrap();
    assert_eq!(repeated_charge.txid, txid);
    assert_eq!(repeated_charge.valor.original, str_value);
    assert_eq!(repeated_charge.calendario.expiracao, expiration_seconds);
}

#[tokio::test]
async fn test_qr_code() {
    let client_id = std::env::var("GERENCIANET_CLIENT_ID")
        .expect("GERENCIANET_CLIENT_ID env variable is not set");
    let client_secret = std::env::var("GERENCIANET_CLIENT_SECRET")
        .expect("GERENCIANET_CLIENT_SECRET env variable is not set");
    let pix_key =
        std::env::var("GERENCIANET_PIX_KEY").expect("GERENCIANET_PIX_KEY env variable is not set");
    let url = std::env::var("GERENCIANET_URL").expect("GERENCIANET_URL env variable is not set");
    let der_base64 = std::env::var("GERENCIANET_KEY_BASE64")
        .expect("GERENCIANET_KEY_BASE64 env variable is not set");
    let der_password = std::env::var("GERENCIANET_KEY_PASSWORD")
        .expect("GERENCIANET_KEY_PASSWORD env variable is not set");
    let gn = Gerencianet::new(
        client_id,
        client_secret,
        url,
        pix_key,
        der_base64,
        der_password,
    );
    let txid = random_string(30);
    let str_value = "1.23";
    let expiration_seconds = 3600;
    let charge = gn
        .create_charge(&str_value, &txid, expiration_seconds)
        .await
        .unwrap();
    let qr_code = gn
        .get_qr_code(charge.loc.unwrap().id)
        .await
        .unwrap()
        .unwrap();
    assert!(qr_code.imagem_qrcode.starts_with("data:image/png;base64,"));
    assert!(!qr_code.qrcode.is_empty());
}

#[tokio::test]
async fn test_cancel() {
    let client_id = std::env::var("GERENCIANET_CLIENT_ID")
        .expect("GERENCIANET_CLIENT_ID env variable is not set");
    let client_secret = std::env::var("GERENCIANET_CLIENT_SECRET")
        .expect("GERENCIANET_CLIENT_SECRET env variable is not set");
    let pix_key =
        std::env::var("GERENCIANET_PIX_KEY").expect("GERENCIANET_PIX_KEY env variable is not set");
    let url = std::env::var("GERENCIANET_URL").expect("GERENCIANET_URL env variable is not set");
    let der_base64 = std::env::var("GERENCIANET_KEY_BASE64")
        .expect("GERENCIANET_KEY_BASE64 env variable is not set");
    let der_password = std::env::var("GERENCIANET_KEY_PASSWORD")
        .expect("GERENCIANET_KEY_PASSWORD env variable is not set");
    let gn = Gerencianet::new(
        client_id,
        client_secret,
        url,
        pix_key,
        der_base64,
        der_password,
    );
    let txid = random_string(30);
    let str_value = "1.23";
    let expiration_seconds = 3600;
    let _charge = gn
        .create_charge(&str_value, &txid, expiration_seconds)
        .await
        .unwrap();
    let cancelled = gn.cancel_charge(txid.as_str()).await.unwrap();
    assert_eq!(cancelled.status, "REMOVIDA_PELO_USUARIO_RECEBEDOR");
}
