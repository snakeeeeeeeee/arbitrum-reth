//! permessage-deflate（RFC 7692）**接收方向**的最小实现。
//!
//! arbitrum-reth 本地补丁（上游 tungstenite 0.28–0.30 都不支持压缩扩展，收到 RSV1=1 的帧直接判
//! `NonZeroReservedBits`）。Robinhood 官方 feed 自 2026-09-17 起强制要求压缩，所以节点直连需要它。
//!
//! 范围刻意很小：
//! - 只解压收到的消息；我们发出去的只有 pong / close（控制帧按 RFC 永不压缩），不需要压缩方向。
//! - 同时认 `permessage-deflate` 和 Arbitrum 中继自定义的 `Arbitrum-permessage-deflate`
//!   （两者线上格式完全一样，实测握手响应除名字外参数一致）。
//! - 支持上下文接管（默认）和 `server_no_context_takeover`（每条消息独立一个 deflate 流）。
//! - `server_max_window_bits` 小于 15 时用 15 位窗口解码同样正确（解码窗口只需 ≥ 编码窗口）。
//! - 只有 `WebSocketConfig::permessage_deflate` 打开、且服务端握手响应里确实同意了扩展时才启用；
//!   否则行为与上游 0.28.0 完全相同（RSV1 仍然报错）。

use flate2::{Decompress, FlushDecompress, Status};

#[cfg(feature = "handshake")]
use crate::error::ProtocolError;
use crate::error::{CapacityError, Error, Result};

/// 我们认的扩展名（大小写不敏感）。
pub const EXTENSION_NAMES: [&str; 2] = ["permessage-deflate", "Arbitrum-permessage-deflate"];

/// RFC 7692 §7.2.2：发送方去掉了每条消息末尾的 `00 00 ff ff`，接收方要补回再解压。
const MESSAGE_TAIL: [u8; 4] = [0x00, 0x00, 0xff, 0xff];

/// 服务端在握手响应里同意的 permessage-deflate 参数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeflateParams {
    /// 响应里的扩展名原文（`permessage-deflate` 或 `Arbitrum-permessage-deflate`）。
    pub name: String,
    /// 服务端每条消息都重新开始压缩上下文 ⇒ 我们每条消息解压完就重置解压器。
    pub server_no_context_takeover: bool,
    /// 客户端（我们）发送方向不接管上下文。我们从不发压缩消息，只记录。
    pub client_no_context_takeover: bool,
    /// 服务端压缩窗口位数（8..=15）。解码一律用 15 位窗口，只做合法性检查。
    pub server_max_window_bits: Option<u8>,
    /// 客户端压缩窗口位数。我们从不压缩，只做合法性检查。
    pub client_max_window_bits: Option<u8>,
}

#[cfg(feature = "handshake")]
impl DeflateParams {
    /// 从握手响应的 `Sec-WebSocket-Extensions` 各个值里找出服务端同意的 deflate 扩展。
    ///
    /// 返回 `Ok(None)`：响应里没有 deflate 扩展（服务端没同意，按普通连接处理）。
    /// 返回 `Err`：有 deflate 扩展但参数不合法 —— RFC 7692 §5 要求客户端此时失败连接。
    /// 其它不认识的扩展保持上游行为：忽略。
    pub fn from_response_headers<'a, I>(values: I) -> Result<Option<Self>>
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        for value in values {
            let text = std::str::from_utf8(value).map_err(|_| invalid_extensions_header())?;
            for extension in text.split(',') {
                let mut parts = extension.split(';');
                let name = parts.next().unwrap_or_default().trim();
                if !EXTENSION_NAMES.iter().any(|known| known.eq_ignore_ascii_case(name)) {
                    continue;
                }
                let mut params = DeflateParams {
                    name: name.to_owned(),
                    server_no_context_takeover: false,
                    client_no_context_takeover: false,
                    server_max_window_bits: None,
                    client_max_window_bits: None,
                };
                for param in parts {
                    let (key, raw_value) = match param.split_once('=') {
                        Some((key, value)) => (key.trim(), Some(value.trim().trim_matches('"'))),
                        None => (param.trim(), None),
                    };
                    match (key.to_ascii_lowercase().as_str(), raw_value) {
                        ("", None) => {}
                        ("server_no_context_takeover", None) => {
                            params.server_no_context_takeover = true
                        }
                        ("client_no_context_takeover", None) => {
                            params.client_no_context_takeover = true
                        }
                        ("server_max_window_bits", Some(bits)) => {
                            params.server_max_window_bits = Some(parse_window_bits(bits)?)
                        }
                        ("client_max_window_bits", Some(bits)) => {
                            params.client_max_window_bits = Some(parse_window_bits(bits)?)
                        }
                        _ => return Err(invalid_extensions_header()),
                    }
                }
                // 服务端只能同意一种；取第一个认得的。
                return Ok(Some(params));
            }
        }
        Ok(None)
    }
}

#[cfg(feature = "handshake")]
fn parse_window_bits(raw: &str) -> Result<u8> {
    match raw.parse::<u8>() {
        Ok(bits) if (8..=15).contains(&bits) => Ok(bits),
        _ => Err(invalid_extensions_header()),
    }
}

#[cfg(feature = "handshake")]
fn invalid_extensions_header() -> Error {
    Error::Protocol(ProtocolError::InvalidHeader(
        http::header::SEC_WEBSOCKET_EXTENSIONS.into(),
    ))
}

fn corrupt(err: impl std::fmt::Display) -> Error {
    Error::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("permessage-deflate: {err}"),
    ))
}

/// 一条连接的解压状态（每条连接一个；上下文接管时跨消息保留 LZ77 窗口）。
#[derive(Debug)]
pub(crate) struct Inflater {
    raw: Decompress,
    reset_per_message: bool,
    /// 发送方用了 BFINAL 结束了 deflate 流：本条消息剩余输入（含补的尾巴）忽略，消息结束时重置。
    stream_ended: bool,
}

impl Inflater {
    pub(crate) fn new(params: &DeflateParams) -> Self {
        Inflater {
            raw: Decompress::new(false),
            reset_per_message: params.server_no_context_takeover,
            stream_ended: false,
        }
    }

    /// 解压一个数据帧的负载，结果追加到 `out`。`last` = 这是本条消息的最后一帧（FIN）。
    /// `limit` 是 `out` 允许的最大长度（防解压炸弹，超了返回 `MessageTooLong`）。
    pub(crate) fn inflate_frame(
        &mut self,
        payload: &[u8],
        last: bool,
        out: &mut Vec<u8>,
        limit: usize,
    ) -> Result<()> {
        let result = self.feed(payload, out, limit).and_then(|()| {
            if last {
                self.feed(&MESSAGE_TAIL, out, limit)
            } else {
                Ok(())
            }
        });
        if last || result.is_err() {
            if self.reset_per_message || self.stream_ended || result.is_err() {
                self.raw.reset(false);
            }
            self.stream_ended = false;
        }
        result
    }

    fn feed(&mut self, mut input: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<()> {
        loop {
            if self.stream_ended {
                return Ok(());
            }
            if out.len() == out.capacity() {
                // 行情 JSON 的压缩比大约 3–5 倍；一次多给点，少走几轮。
                out.reserve(input.len().saturating_mul(4).max(16 * 1024));
            }
            let (in_before, out_before) = (self.raw.total_in(), self.raw.total_out());
            let status =
                self.raw.decompress_vec(input, out, FlushDecompress::Sync).map_err(corrupt)?;
            let consumed = (self.raw.total_in() - in_before) as usize;
            let produced = (self.raw.total_out() - out_before) as usize;
            input = &input[consumed..];
            if out.len() > limit {
                return Err(Error::Capacity(CapacityError::MessageTooLong {
                    size: out.len(),
                    max_size: limit,
                }));
            }
            match status {
                Status::StreamEnd => {
                    self.stream_ended = true;
                    return Ok(());
                }
                Status::Ok | Status::BufError => {
                    let has_room = out.len() < out.capacity();
                    if input.is_empty() && has_room {
                        return Ok(());
                    }
                    if consumed == 0 && produced == 0 && has_room {
                        return Err(corrupt("decoder made no progress"));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compress, Compression, FlushCompress};

    fn params(no_takeover: bool) -> DeflateParams {
        DeflateParams {
            name: "permessage-deflate".into(),
            server_no_context_takeover: no_takeover,
            client_no_context_takeover: no_takeover,
            server_max_window_bits: None,
            client_max_window_bits: None,
        }
    }

    /// 按 RFC 7692 压一条消息：sync flush 后去掉末尾 00 00 ff ff。
    fn compress_message(compressor: &mut Compress, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len() + 64);
        let mut input = data;
        loop {
            out.reserve(1024);
            let before = compressor.total_in();
            let status = compressor.compress_vec(input, &mut out, FlushCompress::Sync).unwrap();
            assert_eq!(status, flate2::Status::Ok);
            input = &input[(compressor.total_in() - before) as usize..];
            if input.is_empty() && out.len() < out.capacity() {
                break;
            }
        }
        assert!(out.ends_with(&MESSAGE_TAIL));
        out.truncate(out.len() - 4);
        out
    }

    #[test]
    #[cfg(feature = "handshake")]
    fn parses_negotiated_parameters() {
        let header: &[u8] =
            b"permessage-deflate; server_no_context_takeover; client_no_context_takeover";
        let p = DeflateParams::from_response_headers([header]).unwrap().unwrap();
        assert_eq!(p.name, "permessage-deflate");
        assert!(p.server_no_context_takeover && p.client_no_context_takeover);

        let header: &[u8] = b"x-other, Arbitrum-permessage-deflate; server_max_window_bits=\"10\"";
        let p = DeflateParams::from_response_headers([header]).unwrap().unwrap();
        assert_eq!(p.name, "Arbitrum-permessage-deflate");
        assert_eq!(p.server_max_window_bits, Some(10));
        assert!(!p.server_no_context_takeover);

        let header: &[u8] = b"x-other; foo=1";
        assert_eq!(DeflateParams::from_response_headers([header]).unwrap(), None);
        assert_eq!(DeflateParams::from_response_headers(std::iter::empty()).unwrap(), None);

        for bad in [
            &b"permessage-deflate; server_max_window_bits=7"[..],
            &b"permessage-deflate; server_max_window_bits"[..],
            &b"permessage-deflate; mystery_param"[..],
        ] {
            assert!(DeflateParams::from_response_headers([bad]).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn inflates_independent_and_context_takeover_streams() {
        let messages: Vec<Vec<u8>> = (0..20)
            .map(|i| format!("{{\"sequenceNumber\":{i},\"payload\":\"{}\"}}", "ab".repeat(500 + i)))
            .map(String::into_bytes)
            .collect();
        for no_takeover in [true, false] {
            let mut compressor = Compress::new(Compression::default(), false);
            let mut inflater = Inflater::new(&params(no_takeover));
            for message in &messages {
                if no_takeover {
                    compressor.reset();
                }
                let wire = compress_message(&mut compressor, message);
                let mut out = Vec::new();
                inflater.inflate_frame(&wire, true, &mut out, usize::MAX).unwrap();
                assert_eq!(&out, message);
            }
        }
    }

    #[test]
    fn inflates_a_message_split_across_frames() {
        let message = "{\"k\":\"".to_string() + &"xyz0123456789".repeat(4000) + "\"}";
        let mut compressor = Compress::new(Compression::default(), false);
        let wire = compress_message(&mut compressor, message.as_bytes());
        let mut inflater = Inflater::new(&params(true));
        let mut out = Vec::new();
        let chunks: Vec<&[u8]> = wire.chunks(97).collect();
        for (i, chunk) in chunks.iter().enumerate() {
            inflater.inflate_frame(chunk, i + 1 == chunks.len(), &mut out, usize::MAX).unwrap();
        }
        assert_eq!(out, message.as_bytes());
    }

    #[test]
    fn rejects_decompression_bombs_and_garbage() {
        let message = vec![b'a'; 1 << 20];
        let mut compressor = Compress::new(Compression::default(), false);
        let wire = compress_message(&mut compressor, &message);
        let mut inflater = Inflater::new(&params(true));
        let mut out = Vec::new();
        let err = inflater.inflate_frame(&wire, true, &mut out, 64 * 1024).unwrap_err();
        assert!(matches!(err, Error::Capacity(CapacityError::MessageTooLong { .. })));

        // 出错后解压器已重置，下一条正常消息仍能解。
        let mut compressor = Compress::new(Compression::default(), false);
        let wire = compress_message(&mut compressor, b"hello");
        let mut out = Vec::new();
        inflater.inflate_frame(&wire, true, &mut out, usize::MAX).unwrap();
        assert_eq!(out, b"hello");

        let mut out = Vec::new();
        assert!(inflater.inflate_frame(&[0xff, 0xff, 0xff, 0xff], true, &mut out, 1 << 20).is_err());
    }

    #[test]
    fn a_final_deflate_block_ends_the_message_and_resets() {
        // 发送方用 BFINAL（Finish）结束：补的尾巴要被忽略，且下一条消息从新上下文开始。
        let mut inflater = Inflater::new(&params(false));
        for text in [&b"first message"[..], &b"second message"[..]] {
            let mut compressor = Compress::new(Compression::default(), false);
            let mut wire = Vec::with_capacity(256);
            compressor.compress_vec(text, &mut wire, FlushCompress::Finish).unwrap();
            let mut out = Vec::new();
            inflater.inflate_frame(&wire, true, &mut out, usize::MAX).unwrap();
            assert_eq!(out, text);
        }
    }
}
