//! arbitrum-reth 本地补丁的测试：permessage-deflate 接收方向。
//!
//! 覆盖：单帧压缩消息、压缩与明文消息交错、压缩消息分片（中间夹控制帧）、上下文接管、
//! 续帧 / 未协商时 RSV1 仍报错（上游行为不变）、真 TCP 上的客户端握手协商
//! （两种扩展名、配置关闭时不启用）。

#![cfg(feature = "handshake")]

use std::{
    io::{self, Cursor, Read, Write},
    net::TcpListener,
    thread,
};

use flate2::{Compress, Compression, FlushCompress};
use tungstenite::{
    client::IntoClientRequest,
    error::{Error, ProtocolError},
    handshake::derive_accept_key,
    protocol::{DeflateParams, Role, WebSocket, WebSocketConfig},
    Message,
};

struct WriteMoc<S>(S);

impl<S> Write for WriteMoc<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<S: Read> Read for WriteMoc<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

/// 服务端 → 客户端的一帧（不加掩码）。
fn frame(opcode: u8, fin: bool, rsv1: bool, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![(u8::from(fin) << 7) | (u8::from(rsv1) << 6) | opcode];
    match payload.len() {
        n if n < 126 => out.push(n as u8),
        n if n <= u16::MAX as usize => {
            out.push(126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            out.push(127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    out.extend_from_slice(payload);
    out
}

/// RFC 7692 压缩一条消息：sync flush，去掉末尾 00 00 ff ff。
fn compress(compressor: &mut Compress, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 64);
    let mut input = data;
    loop {
        out.reserve(1024);
        let before = compressor.total_in();
        compressor.compress_vec(input, &mut out, FlushCompress::Sync).unwrap();
        input = &input[(compressor.total_in() - before) as usize..];
        if input.is_empty() && out.len() < out.capacity() {
            break;
        }
    }
    assert!(out.ends_with(&[0, 0, 0xff, 0xff]));
    out.truncate(out.len() - 4);
    out
}

fn params(no_takeover: bool) -> DeflateParams {
    DeflateParams {
        name: "permessage-deflate".into(),
        server_no_context_takeover: no_takeover,
        client_no_context_takeover: no_takeover,
        server_max_window_bits: None,
        client_max_window_bits: None,
    }
}

fn feed_json(seq: u64) -> String {
    format!(
        "{{\"version\":1,\"messages\":[{{\"sequenceNumber\":{seq},\"message\":{{\"l2Msg\":\"{}\"}}}}]}}",
        "BAAAAAAAAAB4nGNgYGBgZGRkBAAADgAD".repeat(40 + seq as usize % 7)
    )
}

#[test]
fn mixed_compressed_plain_and_fragmented_messages() {
    let mut c = Compress::new(Compression::default(), false);
    let a = feed_json(1);
    let b = feed_json(2);
    let big = feed_json(3).repeat(50);
    let mut wire = Vec::new();
    // 1) 单帧压缩文本
    c.reset();
    wire.extend(frame(0x1, true, true, &compress(&mut c, a.as_bytes())));
    // 2) 明文文本（服务端可以选择不压某条消息）
    wire.extend(frame(0x1, true, false, b.as_bytes()));
    // 3) 压缩文本分三片，中间夹一个 ping
    c.reset();
    let z = compress(&mut c, big.as_bytes());
    let third = z.len() / 3;
    wire.extend(frame(0x1, false, true, &z[..third]));
    wire.extend(frame(0x9, true, false, b"hi"));
    wire.extend(frame(0x0, false, false, &z[third..2 * third]));
    wire.extend(frame(0x0, true, false, &z[2 * third..]));
    // 4) 压缩二进制
    c.reset();
    wire.extend(frame(0x2, true, true, &compress(&mut c, &[1, 2, 3, 250, 251])));

    let mut ws = WebSocket::from_raw_socket(WriteMoc(Cursor::new(wire)), Role::Client, None);
    ws.enable_permessage_deflate(params(true));
    assert_eq!(ws.read().unwrap(), Message::Text(a.into()));
    assert_eq!(ws.read().unwrap(), Message::Text(b.into()));
    assert_eq!(ws.read().unwrap(), Message::Ping(b"hi".to_vec().into()));
    assert_eq!(ws.read().unwrap(), Message::Text(big.into()));
    assert_eq!(ws.read().unwrap(), Message::Binary(vec![1, 2, 3, 250, 251].into()));
}

#[test]
fn context_takeover_keeps_the_window_across_messages() {
    let mut c = Compress::new(Compression::default(), false);
    let messages: Vec<String> = (0..30).map(feed_json).collect();
    let mut wire = Vec::new();
    for m in &messages {
        wire.extend(frame(0x1, true, true, &compress(&mut c, m.as_bytes())));
    }
    let mut ws = WebSocket::from_raw_socket(WriteMoc(Cursor::new(wire)), Role::Client, None);
    ws.enable_permessage_deflate(params(false));
    for m in messages {
        assert_eq!(ws.read().unwrap(), Message::Text(m.into()));
    }
}

#[test]
fn rsv1_is_still_rejected_where_the_rfc_forbids_it() {
    // 未协商：与上游 0.28.0 相同，第一帧就报 NonZeroReservedBits。
    let mut c = Compress::new(Compression::default(), false);
    let z = compress(&mut c, b"{}");
    let wire = frame(0x1, true, true, &z);
    let mut ws = WebSocket::from_raw_socket(WriteMoc(Cursor::new(wire)), Role::Client, None);
    assert!(matches!(ws.read(), Err(Error::Protocol(ProtocolError::NonZeroReservedBits))));

    // 已协商，但 RSV1 出现在续帧上。
    let mut wire = frame(0x1, false, true, &z[..1]);
    wire.extend(frame(0x0, true, true, &z[1..]));
    let mut ws = WebSocket::from_raw_socket(WriteMoc(Cursor::new(wire)), Role::Client, None);
    ws.enable_permessage_deflate(params(true));
    assert!(matches!(ws.read(), Err(Error::Protocol(ProtocolError::NonZeroReservedBits))));

    // 已协商，但 RSV1 出现在控制帧上。
    let wire = frame(0x9, true, true, b"x");
    let mut ws = WebSocket::from_raw_socket(WriteMoc(Cursor::new(wire)), Role::Client, None);
    ws.enable_permessage_deflate(params(true));
    assert!(matches!(ws.read(), Err(Error::Protocol(ProtocolError::NonZeroReservedBits))));
}

/// 在真 TCP 上跑一次客户端握手：服务端按 `response_extension` 回应，然后推两条压缩消息。
fn handshake_roundtrip(
    response_extension: Option<&'static str>,
    config: WebSocketConfig,
) -> Result<(Option<DeflateParams>, String, tungstenite::Result<Message>), Error> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        let mut buf = [0u8; 4096];
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = sock.read(&mut buf).unwrap();
            assert!(n > 0);
            request.extend_from_slice(&buf[..n]);
        }
        let text = String::from_utf8(request).unwrap();
        let key = text
            .lines()
            .find_map(|l| l.strip_prefix("Sec-WebSocket-Key: ").or(l.strip_prefix("sec-websocket-key: ")))
            .unwrap()
            .trim()
            .to_owned();
        let mut response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Accept: {}\r\n",
            derive_accept_key(key.as_bytes())
        );
        if let Some(ext) = response_extension {
            response.push_str(&format!("Sec-WebSocket-Extensions: {ext}\r\n"));
        }
        response.push_str("\r\n");
        let mut c = Compress::new(Compression::default(), false);
        let mut out = response.into_bytes();
        for m in [feed_json(7), feed_json(8)] {
            c.reset();
            out.extend(frame(0x1, true, true, &compress(&mut c, m.as_bytes())));
        }
        sock.write_all(&out).unwrap();
        // 等客户端读完再关
        let _ = sock.read(&mut buf);
        text
    });

    let stream = std::net::TcpStream::connect(addr).unwrap();
    let mut request = format!("ws://{addr}/").into_client_request().unwrap();
    request
        .headers_mut()
        .insert("Sec-WebSocket-Extensions", "permessage-deflate".parse().unwrap());
    request.headers_mut().insert("arbitrum-requested-sequence-number", "42".parse().unwrap());
    let (mut ws, _) = match tungstenite::client::client_with_config(request, stream, Some(config)) {
        Ok(ok) => ok,
        Err(err) => return Err(err.into_handshake_error()),
    };
    let negotiated = ws.permessage_deflate().cloned();
    let first = ws.read();
    if first.is_ok() {
        assert_eq!(ws.read().unwrap(), Message::Text(feed_json(8).into()));
    }
    drop(ws);
    let request_text = server.join().unwrap();
    Ok((negotiated, request_text, first))
}

trait IntoHandshakeError {
    fn into_handshake_error(self) -> Error;
}

impl<S> IntoHandshakeError for tungstenite::HandshakeError<S>
where
    S: tungstenite::handshake::HandshakeRole,
{
    fn into_handshake_error(self) -> Error {
        match self {
            tungstenite::HandshakeError::Failure(err) => err,
            tungstenite::HandshakeError::Interrupted(_) => panic!("blocking socket was interrupted"),
        }
    }
}

#[test]
fn client_handshake_enables_inflate_from_the_response() {
    for name in ["permessage-deflate", "Arbitrum-permessage-deflate"] {
        let ext: &'static str = Box::leak(
            format!("{name}; server_no_context_takeover; client_no_context_takeover").into_boxed_str(),
        );
        let (negotiated, request, first) =
            handshake_roundtrip(Some(ext), WebSocketConfig::default().permessage_deflate(true))
                .unwrap();
        let negotiated = negotiated.expect("deflate negotiated");
        assert_eq!(negotiated.name, name);
        assert!(negotiated.server_no_context_takeover);
        assert!(request.contains("permessage-deflate"));
        assert!(request.contains("arbitrum-requested-sequence-number: 42"));
        assert_eq!(first.unwrap(), Message::Text(feed_json(7).into()));
    }
}

#[test]
fn client_handshake_leaves_upstream_behaviour_when_disabled() {
    // 配置没开：即使服务端同意了扩展也不启用 ⇒ 与上游一样第一帧报错。
    let (negotiated, _, first) = handshake_roundtrip(
        Some("permessage-deflate; server_no_context_takeover"),
        WebSocketConfig::default(),
    )
    .unwrap();
    assert!(negotiated.is_none());
    assert!(matches!(first, Err(Error::Protocol(ProtocolError::NonZeroReservedBits))));

    // 配置开了但服务端没同意：普通连接（这里服务端硬推压缩帧，所以同样报错）。
    let (negotiated, _, first) =
        handshake_roundtrip(None, WebSocketConfig::default().permessage_deflate(true)).unwrap();
    assert!(negotiated.is_none());
    assert!(matches!(first, Err(Error::Protocol(ProtocolError::NonZeroReservedBits))));

    // 服务端回了非法参数：握手失败。
    let result = handshake_roundtrip(
        Some("permessage-deflate; server_max_window_bits=99"),
        WebSocketConfig::default().permessage_deflate(true),
    );
    assert!(
        matches!(result, Err(Error::Protocol(ProtocolError::InvalidHeader(_)))),
        "invalid extension parameters must fail the handshake"
    );
}
