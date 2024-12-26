use std::{
    io::{Read, Write},
    net::TcpStream,
};

use bytes::BytesMut;

use crate::{
    build_auth_basic_req, build_cmd_req, build_init_req, parse_auth_basic_resp, parse_cmd_resp,
    parse_init_resp, Addr, AuthCredential, AuthMethod, Command, IOResult, ProxyConfig, Reply,
};

/// perform connect with
pub fn conn_with<S: Read + Write>(
    stream: &mut S,
    config: &ProxyConfig,
    target_addr: Addr,
    target_port: u16,
) -> IOResult<(Addr, u16)> {
    let methods = match &config.auth {
        None => vec![AuthMethod::none()],
        Some(_) => {
            vec![AuthMethod::none(), AuthMethod::basic()]
        }
    };
    // write/read init req/response
    tracing::debug!("client provide auth {:?} methods", methods);
    let init_req = build_init_req(methods);
    stream.write_all(&init_req)?;

    let mut init_resp_buf = [0u8; 2];
    stream.read_exact(&mut init_resp_buf)?;
    let m = parse_init_resp(init_resp_buf);
    tracing::debug!("server choose {}", m);

    if AuthMethod::is_unavailable(m) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "proxy server return ",
        ));
    }

    if AuthMethod::is_basic(m) {
        match &config.auth {
            None => {
                panic!("client has no auth data but server required auth");
            }
            Some(AuthCredential { user, passwd }) => {
                let auth_req = build_auth_basic_req(user.clone(), passwd.clone());
                stream.write_all(&auth_req)?;

                let mut auth_buf = [0u8; 2];
                stream.read_exact(&mut auth_buf)?;
                let auth_ok = parse_auth_basic_resp(auth_buf);
                if !auth_ok {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "socks5 proxy auth failed",
                    ));
                }
                tracing::debug!("auth completed");
            }
        };
    }

    let cmd_req = build_cmd_req(Command::Connect, target_addr, target_port);
    stream.write_all(&cmd_req)?;
    tracing::debug!("write cmd req done");

    let mut data = BytesMut::new();
    data.resize(5, 0);
    stream.read_exact(&mut data)?;
    match data[3] {
        1 => data.resize(4 + 4 + 2, 0),
        3 => {
            let len = data[4] as usize;
            data.resize(5 + len + 2, 0);
        }
        4 => data.resize(4 + 16 + 2, 0),
        ty => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid addr type {}", ty),
            ))
        }
    }
    stream.read_exact(&mut data[5..])?;
    let (reply, addr, port) = parse_cmd_resp(data)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if !matches!(reply, Reply::Succeeded) {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("server reply not ok {:?}", reply),
        ))
    } else {
        Ok((addr, port))
    }
}

/// create connection with config
pub fn create_conn(
    config: &ProxyConfig,
    target_addr: Addr,
    target_port: u16,
) -> IOResult<(TcpStream, Addr, u16)> {
    let mut stream = TcpStream::connect((config.host.as_str(), config.port))?;
    let (addr, port) = conn_with(&mut stream, config, target_addr, target_port)?;
    Ok((stream, addr, port))
}
