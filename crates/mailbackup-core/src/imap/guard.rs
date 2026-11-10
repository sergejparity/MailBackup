//! Time and size limits for an IMAP connection (issue #72).
//!
//! [`Guarded`] wraps the connection's stream. It fails a read or a write
//! when no byte has moved for the idle timeout, and it charges every byte
//! read to the budget of the command in progress, failing the read once a
//! response is larger than the command can legitimately return. Both errors
//! are I/O errors with recognizable markers ([`classify`]); after either,
//! the session must not be used for another command.
//!
//! A session can have two guards: one directly above TLS and, once
//! `COMPRESS=DEFLATE` is on, one above the decompressor. Both detect idle
//! connections; only the outermost one counts bytes, so the budget applies
//! to what the server's responses really expand to.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Sleep;

/// Budget value meaning "no limit".
const UNLIMITED: i64 = i64::MAX;
const IDLE_MARKER: &str = "IMAP connection idle";
const BUDGET_MARKER: &str = "IMAP response larger than";

/// What the guards of one connection share.
#[derive(Debug)]
pub struct GuardState {
    idle: Duration,
    /// Bytes the command in progress may still read
    remaining: AtomicI64,
    /// The budget it started with, for the error message
    budget: AtomicI64,
    /// The guard (layer) that counts bytes
    counting_layer: AtomicU32,
    next_layer: AtomicU32,
}

impl GuardState {
    pub fn new(idle: Duration) -> Arc<GuardState> {
        Arc::new(GuardState {
            idle,
            remaining: AtomicI64::new(UNLIMITED),
            budget: AtomicI64::new(UNLIMITED),
            counting_layer: AtomicU32::new(0),
            next_layer: AtomicU32::new(0),
        })
    }

    /// The next command may read at most `bytes`.
    pub fn set_budget(&self, bytes: u64) {
        let bytes = i64::try_from(bytes).unwrap_or(UNLIMITED);
        self.budget.store(bytes, Ordering::SeqCst);
        self.remaining.store(bytes, Ordering::SeqCst);
    }

    /// Bytes the current command has read so far.
    pub fn used(&self) -> u64 {
        let budget = self.budget.load(Ordering::SeqCst);
        let remaining = self.remaining.load(Ordering::SeqCst);
        if budget == UNLIMITED {
            return 0;
        }
        (budget.saturating_sub(remaining)).max(0) as u64
    }

    fn charge(&self, layer: u32, n: usize) -> io::Result<()> {
        if layer != self.counting_layer.load(Ordering::SeqCst) || n == 0 {
            return Ok(());
        }
        let budget = self.budget.load(Ordering::SeqCst);
        if budget == UNLIMITED {
            return Ok(());
        }
        let left = self.remaining.fetch_sub(n as i64, Ordering::SeqCst) - n as i64;
        if left < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} the {} bytes the command allows", BUDGET_MARKER, budget),
            ));
        }
        Ok(())
    }
}

/// What a stream error from a guard means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    Idle,
    Budget,
}

/// Whether `e` (or the text of an error that wraps it) came from a guard.
pub fn classify(text: &str) -> Option<Limit> {
    if text.contains(IDLE_MARKER) {
        Some(Limit::Idle)
    } else if text.contains(BUDGET_MARKER) {
        Some(Limit::Budget)
    } else {
        None
    }
}

/// A stream with the limits of a [`GuardState`].
pub struct Guarded<S> {
    inner: S,
    state: Arc<GuardState>,
    layer: u32,
    read_timer: Option<Pin<Box<Sleep>>>,
    write_timer: Option<Pin<Box<Sleep>>>,
}

impl<S> Guarded<S> {
    /// Wraps `inner`; from now on this guard is the one that counts bytes.
    pub fn new(inner: S, state: Arc<GuardState>) -> Self {
        let layer = state.next_layer.fetch_add(1, Ordering::SeqCst) + 1;
        state.counting_layer.store(layer, Ordering::SeqCst);
        Guarded { inner, state, layer, read_timer: None, write_timer: None }
    }
}

impl<S> std::fmt::Debug for Guarded<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Guarded").field("layer", &self.layer).finish()
    }
}

/// Polls the idle timer of a stalled operation, starting it if needed.
fn stalled(timer: &mut Option<Pin<Box<Sleep>>>, idle: Duration, cx: &mut Context<'_>, what: &str) -> Poll<io::Error> {
    let sleep = timer.get_or_insert_with(|| Box::pin(tokio::time::sleep(idle)));
    match sleep.as_mut().poll(cx) {
        Poll::Ready(()) => Poll::Ready(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("{}: nothing {} for {} s", IDLE_MARKER, what, idle.as_secs()),
        )),
        Poll::Pending => Poll::Pending,
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Guarded<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                this.read_timer = None;
                let n = buf.filled().len() - before;
                Poll::Ready(this.state.charge(this.layer, n))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => stalled(&mut this.read_timer, this.state.idle, cx, "received").map(Err),
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Guarded<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_write(cx, data) {
            Poll::Ready(result) => {
                this.write_timer = None;
                Poll::Ready(result)
            }
            Poll::Pending => stalled(&mut this.write_timer, this.state.idle, cx, "sent").map(Err),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Ready(result) => {
                this.write_timer = None;
                Poll::Ready(result)
            }
            Poll::Pending => stalled(&mut this.write_timer, this.state.idle, cx, "sent").map(Err),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test(start_paused = true)]
    async fn a_silent_peer_times_out_and_a_talking_one_does_not() {
        let (client, mut server) = tokio::io::duplex(64);
        let state = GuardState::new(Duration::from_secs(30));
        let mut guarded = Guarded::new(client, state);
        let talker = tokio::spawn(async move {
            for _ in 0..5 {
                tokio::time::sleep(Duration::from_secs(20)).await;
                server.write_all(b"x").await.unwrap();
            }
            server
        });
        let mut buf = [0u8; 1];
        for _ in 0..5 {
            guarded.read_exact(&mut buf).await.expect("a byte every 20 s keeps it alive");
        }
        let _server = talker.await.unwrap();
        let err = guarded.read_exact(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert_eq!(classify(&err.to_string()), Some(Limit::Idle));
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_write_times_out() {
        let (client, _server) = tokio::io::duplex(8);
        let mut guarded = Guarded::new(client, GuardState::new(Duration::from_secs(5)));
        let err = guarded.write_all(&[0u8; 64]).await.unwrap_err();
        assert_eq!(classify(&err.to_string()), Some(Limit::Idle));
    }

    #[tokio::test]
    async fn reads_beyond_the_budget_fail_and_only_the_outer_layer_counts() {
        let (client, mut server) = tokio::io::duplex(1 << 16);
        let state = GuardState::new(Duration::from_secs(30));
        // Two layers, as with compression: only the outer one counts
        let inner = Guarded::new(client, state.clone());
        let mut outer = Guarded::new(inner, state.clone());
        state.set_budget(100);
        server.write_all(&[7u8; 1000]).await.unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 40];
        let err = loop {
            match outer.read(&mut buf).await {
                Ok(n) => got.extend_from_slice(&buf[..n]),
                Err(e) => break e,
            }
        };
        assert_eq!(classify(&err.to_string()), Some(Limit::Budget));
        assert!(got.len() <= 100, "no more than the budget was handed on: {}", got.len());
        assert!(state.used() <= 100 + 40, "consumed at most one read past it: {}", state.used());
    }
}
