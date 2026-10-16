//! Build-and-primitives spike: Opus round trip, cpal device enumeration,
//! and iroh QUIC datagrams between two in-process endpoints.

use std::{
    f32::consts::PI,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use iroh::{endpoint::presets, Endpoint, EndpointAddr, RelayMode, SecretKey};

const ALPN: &[u8] = b"spike/call/1";
const FRAME: usize = 960; // 20 ms at 48 kHz mono
const DATAGRAMS: u32 = 1000;

fn opus_roundtrip() -> Result<()> {
    let mut enc = opus::Encoder::new(48_000, opus::Channels::Mono, opus::Application::Voip)
        .context("encoder")?;
    enc.set_bitrate(opus::Bitrate::Bits(24_000)).context("bitrate")?;
    enc.set_inband_fec(true).context("fec")?;
    let mut dec = opus::Decoder::new(48_000, opus::Channels::Mono).context("decoder")?;

    let frames = 500usize; // 10 s of audio
    let mut pcm = vec![0i16; FRAME];
    let mut out = vec![0i16; FRAME];
    let mut packet = vec![0u8; 1275];
    let (mut min_len, mut max_len, mut total) = (usize::MAX, 0usize, 0usize);
    let mut energy_in = 0f64;
    let mut energy_out = 0f64;
    let t0 = Instant::now();
    for f in 0..frames {
        for (i, s) in pcm.iter_mut().enumerate() {
            let n = (f * FRAME + i) as f32;
            *s = ((2.0 * PI * 440.0 * n / 48_000.0).sin() * 12_000.0) as i16;
        }
        let len = enc.encode(&pcm, &mut packet).context("encode")?;
        if len == 0 {
            bail!("empty packet at frame {f}");
        }
        let got = dec.decode(&packet[..len], &mut out, false).context("decode")?;
        if got != FRAME {
            bail!("decoded {got} samples, expected {FRAME}");
        }
        min_len = min_len.min(len);
        max_len = max_len.max(len);
        total += len;
        if f >= 10 {
            energy_in += pcm.iter().map(|&s| (s as f64).powi(2)).sum::<f64>();
            energy_out += out.iter().map(|&s| (s as f64).powi(2)).sum::<f64>();
        }
    }
    let ratio = energy_out / energy_in;
    println!(
        "RESULT opus frames={frames} samples_per_frame={FRAME} packet_bytes min={min_len} max={max_len} avg={:.1} energy_ratio={ratio:.3} elapsed_ms={}",
        total as f64 / frames as f64,
        t0.elapsed().as_millis()
    );
    if !(0.3..3.0).contains(&ratio) {
        bail!("decoded energy ratio {ratio} is implausible");
    }
    Ok(())
}

fn cpal_enumerate() {
    use cpal::traits::HostTrait;
    let hosts = cpal::available_hosts();
    println!("RESULT cpal available_hosts={hosts:?}");
    let host = cpal::default_host();
    let ins = host.input_devices().map(|d| d.count());
    let outs = host.output_devices().map(|d| d.count());
    println!(
        "RESULT cpal host={:?} input_devices={:?} output_devices={:?} default_in={} default_out={}",
        host.id(),
        ins.as_ref().map_err(|e| e.to_string()),
        outs.as_ref().map_err(|e| e.to_string()),
        host.default_input_device().is_some(),
        host.default_output_device().is_some()
    );
}

async fn make_endpoint(seed: u8) -> Result<(Endpoint, SecretKey)> {
    let sk = SecretKey::from_bytes(&[seed; 32]);
    let ep = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .secret_key(sk.clone())
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .context("bind")?;
    Ok((ep, sk))
}

async fn datagrams() -> Result<()> {
    let (server, ssk) = make_endpoint(1).await?;
    let (client, _csk) = make_endpoint(2).await?;

    let port = server
        .bound_sockets()
        .iter()
        .find(|a| a.is_ipv4())
        .map(|a| a.port())
        .context("no ipv4 socket bound")?;
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    println!("RESULT iroh bound_sockets={:?} target={target}", server.bound_sockets());

    // Echo server.
    let srv = server.clone();
    let echo = tokio::spawn(async move {
        let incoming = srv.accept().await.context("no incoming")?;
        let conn = incoming.await.context("handshake")?;
        let max = conn.max_datagram_size();
        let mut n = 0u32;
        loop {
            match tokio::time::timeout(Duration::from_secs(3), conn.read_datagram()).await {
                Ok(Ok(d)) => {
                    conn.send_datagram(d).ok();
                    n += 1;
                }
                _ => break,
            }
        }
        anyhow::Ok((n, max))
    });

    let addr = EndpointAddr::new(ssk.public()).with_ip_addr(target);
    let t0 = Instant::now();
    let conn = tokio::time::timeout(Duration::from_secs(15), client.connect(addr, ALPN))
        .await
        .context("connect timed out")?
        .context("connect")?;
    let connect_ms = t0.elapsed().as_millis();
    let max_size = conn.max_datagram_size();
    println!("RESULT iroh connect_ms={connect_ms} client_max_datagram_size={max_size:?}");

    let sender = conn.clone();
    let send_task = tokio::spawn(async move {
        let mut send_err = 0u32;
        for seq in 0..DATAGRAMS {
            let mut buf = vec![0u8; 100];
            buf[..4].copy_from_slice(&seq.to_be_bytes());
            if sender.send_datagram(Bytes::from(buf)).is_err() {
                send_err += 1;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        send_err
    });

    let mut seen = vec![false; DATAGRAMS as usize];
    let mut got = 0u32;
    let t1 = Instant::now();
    loop {
        match tokio::time::timeout(Duration::from_secs(2), conn.read_datagram()).await {
            Ok(Ok(d)) if d.len() >= 4 => {
                let seq = u32::from_be_bytes([d[0], d[1], d[2], d[3]]) as usize;
                if seq < seen.len() && !seen[seq] {
                    seen[seq] = true;
                    got += 1;
                }
                if got == DATAGRAMS {
                    break;
                }
            }
            _ => break,
        }
    }
    let send_err = send_task.await?;
    let (echoed, srv_max) = echo.await??;
    let loss = 100.0 * (DATAGRAMS - got) as f64 / DATAGRAMS as f64;
    println!(
        "RESULT iroh datagrams sent={DATAGRAMS} send_errors={send_err} server_echoed={echoed} round_trip_received={got} loss_pct={loss:.2} server_max_datagram_size={srv_max:?} elapsed_ms={}",
        t1.elapsed().as_millis()
    );
    conn.close(0u32.into(), b"done");
    client.close().await;
    server.close().await;
    if got < DATAGRAMS / 2 {
        bail!("only {got}/{DATAGRAMS} datagrams made the round trip");
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut failed = false;
    if let Err(e) = opus_roundtrip() {
        println!("FAIL opus: {e:#}");
        failed = true;
    }
    cpal_enumerate();
    if let Err(e) = datagrams().await {
        println!("FAIL iroh: {e:#}");
        failed = true;
    }
    if failed {
        std::process::exit(1);
    }
    println!("ALL OK");
    Ok(())
}
