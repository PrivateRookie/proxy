//! support http connection

#![warn(missing_docs)]

use bytes::BytesMut;

/// simple wrapper of [std::io::Result]
pub type IOResult<T> = std::io::Result<T>;

/// http proxy connection config
/// contains, auth data
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// proxy host
    /// ipv6 address should be wrapped with `[]`
    pub host: String,
    /// proxy port
    pub port: u16,
    /// auth credential
    pub auth: AuthCredential,
    /// set `proxy-connection` header `keep-alive`
    pub keep_alive: bool,
}

impl ProxyConfig {
    /// return request string
    pub fn req_str(&self, target: &str) -> String {
        let mut builder = http::request::Builder::new()
            .method("CONNECT")
            .uri(target)
            .header("host", target);
        if self.keep_alive {
            builder = builder.header("proxy-connection", "keep-alive")
        }
        builder = self.auth.config_req(builder);
        let req = builder.body(()).expect("invalid request");
        format!("{}", SerdeWrapper(req))
    }
}

/// auth credential data
///
/// see [doc](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Authentication)
#[derive(Debug, Clone)]
pub enum AuthCredential {
    /// no auth
    None,
    /// basic auth
    /// see [RFC](https://datatracker.ietf.org/doc/html/rfc7617)
    Basic {
        /// user name
        user: String,
        /// password
        passwd: String,
    },
}

impl AuthCredential {
    /// config request by auth credential
    pub fn config_req(&self, builder: http::request::Builder) -> http::request::Builder {
        match self {
            AuthCredential::None => builder,
            AuthCredential::Basic { user, passwd } => {
                let auth = format!("{}:{}", user, passwd);
                let auth = base64::encode(auth.as_bytes());
                builder.header("proxy-authorization", format!("basic {}", auth))
            }
        }
    }
}

struct SerdeWrapper(http::request::Request<()>);

impl std::fmt::Display for SerdeWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let req = &self.0;
        write!(
            f,
            "{method} {path} {version:?}\r\n{headers}\r\n\r\n",
            method = req.method(),
            path = req.uri().to_string(),
            version = req.version(),
            headers = req
                .headers()
                .iter()
                .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or_default()))
                .collect::<Vec<_>>()
                .join("\r\n")
        )
    }
}

fn parse_resp(data: BytesMut) -> Result<http::response::Response<()>, httparse::Error> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut headers);
    resp.parse(&data)?;
    let mut resp_builder = http::Response::builder()
        .status(resp.code.unwrap_or_default())
        .version(match resp.version.unwrap_or(1) {
            0 => http::Version::HTTP_10,
            1 => http::Version::HTTP_11,
            v => {
                tracing::warn!("unknown http 1.{} version", v);
                http::Version::HTTP_11
            }
        });
    for header in resp.headers.iter() {
        resp_builder = resp_builder.header(header.name, header.value);
    }
    Ok(resp_builder.body(()).unwrap())
}

fn check_resp(parts: http::response::Parts) -> IOResult<()> {
    let status = parts.status;
    if status.as_u16() != 200 {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("proxy server response not success {}", status),
        ))
    } else {
        Ok(())
    }
}

#[cfg(feature = "sync")]
mod sync {
    use std::{
        io::{Read, Write},
        net::TcpStream,
    };

    use bytes::{BufMut, BytesMut};

    use super::ProxyConfig;
    use crate::{check_resp, parse_resp, IOResult};

    fn poll_resp<S: Read>(stream: &mut S) -> IOResult<BytesMut> {
        let mut resp = BytesMut::new();
        let mut buf = [0; 1];
        loop {
            let count = stream.read(&mut buf)?;
            if count > 0 {
                resp.put_u8(buf[0]);
                if resp.ends_with(&[b'\r', b'\n', b'\r', b'\n']) {
                    break Ok(resp);
                }
            } else {
                return Err(std::io::Error::new(std::io::ErrorKind::Other, "read eof"));
            }
        }
    }

    /// perform http proxy connect over passed stream
    pub fn connect_with<S: Read + Write>(
        stream: &mut S,
        config: &ProxyConfig,
        target: &str,
    ) -> IOResult<()> {
        let req_str = config.req_str(target);
        tracing::debug!("send req\n{}", req_str);
        stream.write_all(req_str.as_bytes())?;
        let resp = poll_resp(stream)?;
        let resp = parse_resp(resp)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        tracing::debug!("proxy server response\n{:?}", resp);
        let (parts, _) = resp.into_parts();
        check_resp(parts)
    }

    /// create connection from proxy config
    pub fn create_conn(config: &ProxyConfig, target: &str) -> IOResult<TcpStream> {
        let mut stream = TcpStream::connect((config.host.clone(), config.port))?;
        connect_with(&mut stream, config, target)?;
        Ok(stream)
    }
}

#[cfg(feature = "sync")]
pub use sync::*;

#[cfg(feature = "async")]
mod async_ {
    use bytes::{BufMut, BytesMut};
    use tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
        net::TcpStream,
    };

    use crate::{check_resp, parse_resp, IOResult, ProxyConfig};

    async fn poll_resp<S: AsyncRead + Unpin>(stream: &mut S) -> IOResult<BytesMut> {
        let mut resp = BytesMut::new();
        let mut buf = [0; 1];
        loop {
            let count = stream.read(&mut buf).await?;
            if count > 0 {
                resp.put_u8(buf[0]);
                if resp.ends_with(&[b'\r', b'\n', b'\r', b'\n']) {
                    break Ok(resp);
                }
            } else {
                return Err(std::io::Error::new(std::io::ErrorKind::Other, "read eof"));
            }
        }
    }

    /// perform http proxy connect
    pub async fn async_connect_with<S: AsyncWrite + AsyncRead + Unpin>(
        stream: &mut S,
        config: &ProxyConfig,
        target: &str,
    ) -> IOResult<()> {
        let req_str = config.req_str(target);
        tracing::debug!("send req\n{}", req_str);
        stream.write_all(req_str.as_bytes()).await?;
        let resp = poll_resp(stream).await?;
        let resp = parse_resp(resp)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        tracing::debug!("proxy server response\n{:?}", resp);
        let (parts, _) = resp.into_parts();
        check_resp(parts)
    }

    /// create connection from proxy config
    pub async fn async_create_conn(config: &ProxyConfig, target: &str) -> IOResult<TcpStream> {
        let mut stream = TcpStream::connect((config.host.clone(), config.port)).await?;
        async_connect_with(&mut stream, config, target).await?;
        Ok(stream)
    }
}

#[cfg(feature = "async")]
pub use async_::*;
