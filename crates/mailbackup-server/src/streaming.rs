//! Large responses without holding them in memory (issue #78).
//!
//! [`ChannelWriter`] is the `std::io::Write` end of a bounded channel: a
//! blocking producer (the mbox exporter) writes into it and blocks while the
//! client is slower; [`channel_body`] is the response body reading the other
//! end. Memory stays at a few chunks of at most [`CHUNK_BYTES`], however
//! large a single write is. When the client goes away, the body is
//! dropped, the next write fails, and the producer stops.
//!
//! [`save_body`] writes a response body to a new file chunk by chunk, for the
//! desktop app's downloads.

use axum::body::{Body, Bytes};
use futures_util::StreamExt;
use std::io;
use std::path::Path;
use tokio::sync::mpsc;

/// Size of the chunks sent to the client.
pub const CHUNK_BYTES: usize = 256 * 1024;
/// Chunks in flight between producer and client.
pub const CHANNEL_CHUNKS: usize = 4;

type Chunk = Result<Bytes, io::Error>;

/// The writing end; see the module docs. Call [`ChannelWriter::fail`] to end
/// the body with an error, so the client sees a failed transfer rather than
/// a complete-looking short file.
pub struct ChannelWriter {
    tx: mpsc::Sender<Chunk>,
    buf: Vec<u8>,
}

/// A bounded channel: the writer for a blocking producer and the body.
pub fn channel() -> (ChannelWriter, Body) {
    let (tx, rx) = mpsc::channel::<Chunk>(CHANNEL_CHUNKS);
    let stream = futures_util::stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|chunk| (chunk, rx)) });
    (ChannelWriter { tx, buf: Vec::with_capacity(CHUNK_BYTES) }, Body::from_stream(stream))
}

impl ChannelWriter {
    fn send(&mut self, chunk: Chunk) -> io::Result<()> {
        self.tx
            .blocking_send(chunk)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "the client stopped reading"))
    }

    fn send_buffer(&mut self) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let chunk = Bytes::from(std::mem::replace(&mut self.buf, Vec::with_capacity(CHUNK_BYTES)));
        self.send(Ok(chunk))
    }

    /// Ends the body with an error: the transfer fails instead of ending.
    pub fn fail(mut self, why: String) {
        self.buf.clear();
        let _ = self.send(Err(io::Error::other(why)));
    }

    /// Whether the client is gone (the body was dropped).
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }
}

impl io::Write for ChannelWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.tx.is_closed() {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "the client stopped reading"));
        }
        // Never more than one chunk buffered: a large write (a long line
        // without breaks) is taken a chunk at a time, each sent, and waited
        // for, before the rest (`write_all` comes back for it)
        let taken = data.len().min(CHUNK_BYTES - self.buf.len());
        self.buf.extend_from_slice(&data[..taken]);
        if self.buf.len() == CHUNK_BYTES {
            self.send_buffer()?;
        }
        Ok(taken)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.send_buffer()
    }
}

/// Writes `body` to a new file at `path`, chunk by chunk. Fails if anything
/// exists at `path` (and then leaves it alone); a file it created but
/// couldn't complete is removed.
pub async fn save_body(body: Body, path: &Path) -> io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut file = tokio::fs::OpenOptions::new().write(true).create_new(true).open(path).await?;
    let result = async {
        let mut stream = body.into_data_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(io::Error::other)?;
            file.write_all(&chunk).await?;
        }
        file.flush().await?;
        file.sync_all().await
    }
    .await;
    if let Err(e) = result {
        drop(file);
        let _ = tokio::fs::remove_file(path).await;
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn written_bytes_arrive_in_order_and_in_chunks() {
        let (writer, body) = channel();
        let producer = tokio::task::spawn_blocking(move || {
            let mut writer = writer;
            for i in 0..1000u32 {
                writer.write_all(&i.to_le_bytes().repeat(256)).unwrap();
            }
            writer.flush().unwrap();
        });
        let collected = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        producer.await.unwrap();
        let expected: Vec<u8> = (0..1000u32).flat_map(|i| i.to_le_bytes().repeat(256)).collect();
        assert_eq!(collected.as_ref(), expected.as_slice());
    }

    /// The chunks of a body, as the client receives them.
    async fn chunks(body: Body) -> Vec<Bytes> {
        body.into_data_stream().map(|c| c.unwrap()).collect().await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn one_large_write_is_sent_in_chunks_of_at_most_chunk_bytes() {
        let (writer, body) = channel();
        let data: Vec<u8> = (0..CHUNK_BYTES * 10 + 123).map(|i| (i % 251) as u8).collect();
        let expected = data.clone();
        let producer = tokio::task::spawn_blocking(move || {
            let mut writer = writer;
            writer.write_all(&data).unwrap();
            writer.flush().unwrap();
        });
        let received = chunks(body).await;
        producer.await.unwrap();
        assert!(received.iter().all(|c| c.len() <= CHUNK_BYTES), "sizes: {:?}", received.iter().map(Bytes::len).collect::<Vec<_>>());
        assert_eq!(received.concat(), expected);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_mbox_with_long_unbroken_lines_streams_in_bounded_chunks() {
        // A message whose body is one 3 MB line
        let mut eml = b"From: a@example.com\r\nSubject: long\r\n\r\n".to_vec();
        eml.extend(std::iter::repeat_n(b'x', 3 * 1024 * 1024));
        eml.extend(b"\r\n");
        let (writer, body) = channel();
        let producer = tokio::task::spawn_blocking(move || {
            let mut writer = writer;
            mailbackup_core::mbox::write_message(&mut writer, &eml).unwrap();
            writer.flush().unwrap();
        });
        let received = chunks(body).await;
        producer.await.unwrap();
        assert!(received.iter().all(|c| c.len() <= CHUNK_BYTES));
        assert!(received.iter().map(Bytes::len).sum::<usize>() > 3 * 1024 * 1024);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dropped_body_stops_one_large_write_within_the_bound() {
        let (writer, body) = channel();
        drop(body);
        let accepted = tokio::task::spawn_blocking(move || {
            let mut writer = writer;
            let data = vec![0u8; 64 * 1024 * 1024];
            let mut accepted = 0usize;
            while accepted < data.len() {
                match writer.write(&data[accepted..]) {
                    Ok(n) => accepted += n,
                    Err(_) => break,
                }
            }
            accepted
        })
        .await
        .unwrap();
        assert!(accepted <= CHUNK_BYTES * (CHANNEL_CHUNKS + 1), "took {} bytes after the client left", accepted);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dropped_body_stops_the_producer() {
        let (writer, body) = channel();
        drop(body);
        let written = tokio::task::spawn_blocking(move || {
            let mut writer = writer;
            let mut written = 0usize;
            for _ in 0..10_000 {
                if writer.write_all(&[0u8; 64 * 1024]).is_err() {
                    break;
                }
                written += 64 * 1024;
            }
            written
        })
        .await
        .unwrap();
        assert!(written <= CHUNK_BYTES * (CHANNEL_CHUNKS + 1), "stopped early: {} bytes", written);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_producer_fails_the_body() {
        let (writer, body) = channel();
        tokio::task::spawn_blocking(move || {
            let mut writer = writer;
            writer.write_all(b"partial").unwrap();
            writer.flush().unwrap();
            writer.fail("disk error".to_string());
        });
        assert!(axum::body::to_bytes(body, usize::MAX).await.is_err(), "not a complete-looking body");
    }

    #[tokio::test]
    async fn save_body_writes_a_new_file_and_never_touches_an_existing_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.mbox");
        save_body(Body::from("hello"), &path).await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"hello");

        let err = save_body(Body::from("other"), &path).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap(), b"hello", "left alone");

        // A body that fails part-way leaves no file of its own behind
        let failing = Body::from_stream(futures_util::stream::iter(vec![
            Ok::<_, io::Error>(Bytes::from_static(b"part")),
            Err(io::Error::other("gone")),
        ]));
        let partial = dir.path().join("partial.mbox");
        assert!(save_body(failing, &partial).await.is_err());
        assert!(!partial.exists());
    }
}
