//! socks5 proxy client

#![warn(missing_docs)]

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use bytes::{Buf, BufMut, BytesMut};

#[cfg(feature = "async")]
mod async_;
#[cfg(feature = "async")]
pub use async_::*;

#[cfg(feature = "sync")]
mod sync;
#[cfg(feature = "sync")]
pub use sync::*;

/// socks5 protocol version
pub const VERS: u8 = 0x05;
/// simple [std::io::Result] wrapper
pub type IOResult<T> = std::io::Result<T>;

/// socks5 auth method
pub struct AuthMethod;

impl AuthMethod {
    /// do not require auth
    pub fn none() -> u8 {
        0
    }

    /// check method is none
    pub fn is_none(m: u8) -> bool {
        m == 0
    }

    /// GSSAPI auth
    pub fn gssapi() -> u8 {
        1
    }

    /// check method is gssapi
    pub fn is_gssapi(m: u8) -> bool {
        m == 1
    }

    /// username, password auth
    pub fn basic() -> u8 {
        2
    }

    /// check method is basic auth
    pub fn is_basic(m: u8) -> bool {
        m == 2
    }

    /// check method is IANA reserved
    pub fn is_iana_reserved(m: u8) -> bool {
        m >= 0x3 && m <= 0x7f
    }

    /// check method is self reserved
    pub fn is_reserved(m: u8) -> bool {
        m >= 0x8 && m <= 0xfe
    }

    /// check method is unavailable
    pub fn is_unavailable(m: u8) -> bool {
        m == 0xff
    }

    /// no acceptable auth method
    pub fn unavailable() -> u8 {
        0xff
    }
}

fn build_init_req(methods: Vec<u8>) -> BytesMut {
    assert!(methods.len() <= 255);
    let mut buf = BytesMut::with_capacity(2 + methods.len());
    buf.put_u8(VERS);
    buf.put_u8(methods.len() as u8);
    buf.extend_from_slice(&methods);
    buf
}

fn parse_init_resp(data: [u8; 2]) -> u8 {
    assert_eq!(data[0], VERS);
    data[1]
}

fn build_auth_basic_req(username: String, password: String) -> BytesMut {
    assert!(username.as_bytes().len() <= 255);
    assert!(password.as_bytes().len() <= 255);
    let mut data = BytesMut::new();
    data.put_u8(1);
    data.put_u8(username.as_bytes().len() as u8);
    data.extend_from_slice(username.as_bytes());
    data.put_u8(password.as_bytes().len() as u8);
    data.extend_from_slice(password.as_bytes());
    data
}

fn parse_auth_basic_resp(data: [u8; 2]) -> bool {
    assert_eq!(data[0], 01);
    data[1] == 0
}

/// socks5 dest addr
pub enum Addr {
    /// ipv4 addr 4 bytes
    V4(Ipv4Addr),
    /// hostname, first bytes is hostname len
    Host(String),
    /// ipv6 addr 16 bytes
    V6(Ipv6Addr),
}

impl From<&str> for Addr {
    fn from(addr: &str) -> Self {
        Ipv4Addr::from_str(addr)
            .map(Addr::V4)
            .or_else(|_| Ipv6Addr::from_str(addr).map(Addr::V6))
            .unwrap_or(Addr::Host(addr.to_string()))
    }
}

impl Addr {
    /// write addr to buf with socks5 protocol
    pub fn serde(&self, buf: &mut BytesMut) {
        match self {
            Addr::V4(addr) => {
                buf.put_u8(1);
                buf.extend_from_slice(&addr.octets());
            }
            Addr::Host(host) => {
                buf.put_u8(03);
                let data = host.as_bytes();
                assert!(data.len() <= 255);
                buf.put_u8(data.len() as u8);
                buf.extend_from_slice(data);
            }
            Addr::V6(addr) => {
                buf.put_u8(04);
                buf.extend_from_slice(&addr.octets());
            }
        }
    }

    /// read addr from buf
    pub fn de_serde(buf: &mut BytesMut) -> Result<Self, String> {
        let ty = buf.get_u8();
        match ty {
            1 => {
                let mut addr = [0u8; 4];
                for i in 0..4 {
                    addr[i] = buf.get_u8();
                }
                Ok(Self::V4(Ipv4Addr::from(addr)))
            }
            3 => {
                let len = buf.get_u8() as usize;
                let data = buf[..len].to_vec();
                String::from_utf8(data)
                    .map(Self::Host)
                    .map_err(|_| "invalid utf8 hostname".to_string())
            }
            4 => {
                let mut addr = [0u8; 16];
                for i in 0..16 {
                    addr[i] = buf.get_u8();
                }
                Ok(Self::V6(Ipv6Addr::from(addr)))
            }
            _ => Err(format!("invalid addr type {}", ty)),
        }
    }
}

/// socks command
#[derive(Debug, Clone)]
pub enum Command {
    /// connect
    Connect,
    /// bind(wip)
    Bind,
    /// UDP(wip)
    UdpAssociate,
}

impl Command {
    /// cast command as u8
    pub fn as_u8(&self) -> u8 {
        match self {
            Command::Connect => 1,
            Command::Bind => 2,
            Command::UdpAssociate => 3,
        }
    }

    /// perform cast
    pub fn from_u8(cmd: u8) -> Result<Self, u8> {
        match cmd {
            1 => Ok(Self::Connect),
            2 => Ok(Self::Bind),
            3 => Ok(Self::UdpAssociate),
            _ => Err(cmd),
        }
    }
}

fn build_cmd_req(cmd: Command, addr: Addr, port: u16) -> BytesMut {
    let mut data = BytesMut::new();
    data.put_u8(VERS);
    data.put_u8(cmd.as_u8());
    data.put_u8(0);
    addr.serde(&mut data);
    data.put_u16(port);
    data
}

/// command request response status
#[derive(Debug, Clone)]
pub enum Reply {
    /// succeeded
    Succeeded,
    /// general SOCKS server failure
    ProxyServerFail,
    /// connection not allowed by rule set
    RuleReject,
    /// Network unreachable
    NetworkUnreachable,
    /// Host unreachable
    HostUnreachable,
    /// Connection refused
    ConnectRefuse,
    /// TTL expired
    TTLExpired,
    /// Command not supported
    CommandNotSupported,
    /// Address type not supported
    AddrTypeNotSupported,
    /// X'09' to X'FF' unassigned
    Unassigned(u8),
}

impl Reply {
    /// cast to u8
    pub fn as_u8(&self) -> u8 {
        match self {
            Reply::Succeeded => 0,
            Reply::ProxyServerFail => 1,
            Reply::RuleReject => 2,
            Reply::NetworkUnreachable => 3,
            Reply::HostUnreachable => 4,
            Reply::ConnectRefuse => 5,
            Reply::TTLExpired => 6,
            Reply::CommandNotSupported => 7,
            Reply::AddrTypeNotSupported => 8,
            Reply::Unassigned(x) => *x,
        }
    }

    /// cast from u8
    pub fn from_u8(x: u8) -> Self {
        match x {
            0 => Self::Succeeded,
            1 => Self::ProxyServerFail,
            2 => Self::RuleReject,
            3 => Self::NetworkUnreachable,
            4 => Self::HostUnreachable,
            5 => Self::ConnectRefuse,
            6 => Self::TTLExpired,
            7 => Self::CommandNotSupported,
            8 => Self::AddrTypeNotSupported,
            _ => Self::Unassigned(x),
        }
    }
}

fn parse_cmd_resp(mut data: BytesMut) -> Result<(Reply, Addr, u16), String> {
    let ver = data.get_u8();
    assert_eq!(ver, VERS);
    let reply = Reply::from_u8(data.get_u8());
    let rsv = data.get_u8();
    assert_eq!(rsv, 0);
    let addr = Addr::de_serde(&mut data)?;
    let port = data.get_u16();
    Ok((reply, addr, port))
}

/// proxy connection config
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ser", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "ser", serde(tag = "type"))]
pub struct ProxyConfig {
    /// proxy server host
    /// ipv6 should be wrapped by `[]`
    pub host: String,
    /// proxy server port
    pub port: u16,

    /// proxy server auth credential
    pub auth: AuthCredential,
}

/// proxy server auth config
#[derive(Debug, Clone)]
#[cfg_attr(feature = "ser", derive(serde::Serialize, serde::Deserialize))]
pub enum AuthCredential {
    /// no auth
    None,

    /// username password auth
    Basic {
        /// username
        user: String,
        /// password
        passwd: String,
    },
}
