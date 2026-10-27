//! File-backed raw segment bodies. Readers pin a file version, not its text.

use std::fs::{File, Metadata};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use futures_util::stream;
use ikigai_core::{Body, ByteStream, ContentHasher, ContentId, Error, Replay, Result};

use crate::line::{Header, Line};
use crate::segments::MAX_SEGMENT_BYTES;
use crate::Vocabulary;

const CHUNK_BYTES: usize = 64 * 1024;

pub(crate) struct SegmentBody {
    path: PathBuf,
    version: Metadata,
    validator: ContentId,
    chunk_bytes: usize,
}

fn io(error: std::io::Error) -> Error {
    Error::Endpoint(format!("reading log segment: {error}"))
}

fn changed() -> Error {
    Error::Conflict("log segment changed while reading its body".into())
}

fn over() -> Error {
    Error::OverBudget {
        detail: "log segment exceeds its input or working memory budget".into(),
    }
}

fn same_version(a: &Metadata, b: &Metadata) -> bool {
    let same = a.len() == b.len() && a.modified().ok() == b.modified().ok();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        same && a.dev() == b.dev()
            && a.ino() == b.ino()
            && a.ctime() == b.ctime()
            && a.ctime_nsec() == b.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        same && a.created().ok() == b.created().ok()
    }
}

impl SegmentBody {
    /// Hash and validate UTF-8 one line at a time, using the same line/header
    /// parsers and completion rule as the bytes path. No segment-sized buffer
    /// is retained. An unusually long line/header must fit the run's pool.
    pub(crate) fn prepare(
        path: &Path,
        vocabulary: &Vocabulary,
        memory_bytes: usize,
    ) -> Result<(Self, bool)> {
        let file = File::open(path).map_err(io)?;
        let version = file.metadata().map_err(io)?;
        if version.len() > MAX_SEGMENT_BYTES as u64 {
            return Err(over());
        }
        if memory_bytes == 0 {
            return Err(over());
        }
        let chunk_bytes = CHUNK_BYTES.min((memory_bytes / 4).max(1));
        let mut reader = BufReader::with_capacity(chunk_bytes, file);
        let mut hasher = ContentHasher::new();
        let mut seen = 0;
        let mut header_text = String::new();
        let mut header = None;
        let mut in_header = true;
        let mut ended = false;
        let mut after_end = false;
        let mut sealed_after = false;
        loop {
            let mut line = Vec::new();
            let limit = (MAX_SEGMENT_BYTES - seen)
                .min(memory_bytes.saturating_sub(chunk_bytes + header_text.len()));
            let n = reader
                .by_ref()
                .take(limit as u64 + 1)
                .read_until(b'\n', &mut line)
                .map_err(io)?;
            if n == 0 {
                break;
            }
            if n > limit {
                return Err(over());
            }
            seen += n;
            // Check the byte bound before decoding, including a malformed
            // sentinel byte appended while this scan was in flight.
            hasher.update(&line);
            let line = String::from_utf8(line).map_err(|e| Error::Endpoint(e.to_string()))?;
            let raw = line.trim_end_matches(['\n', '\r']);
            if in_header {
                let blank = raw.trim().is_empty();
                header_text.push_str(&line);
                if blank {
                    header = Header::parse(&header_text).ok().map(|(h, _)| h);
                    header_text = String::new();
                    in_header = false;
                }
            } else if let Some(header) = &header {
                match Line::parse(raw, &header.prefixes) {
                    Ok(Line::Entry(entry)) => {
                        after_end |= ended;
                        ended |= crate::chain::is_an_end(&entry.class, vocabulary);
                    }
                    Ok(Line::Seal(_)) if ended => sealed_after = true,
                    _ => {}
                }
            }
        }
        if seen as u64 != version.len()
            || !same_version(&version, &reader.get_ref().metadata().map_err(io)?)
        {
            return Err(changed());
        }
        Ok((
            Self {
                path: path.into(),
                version,
                validator: hasher.finish(),
                chunk_bytes,
            },
            ended && sealed_after && !after_end,
        ))
    }

    fn reader(&self, offset: u64) -> ByteStream {
        let opened = (|| {
            let mut file = File::open(&self.path).map_err(|_| changed())?;
            if !same_version(&self.version, &file.metadata().map_err(io)?) {
                return Err(changed());
            }
            file.seek(SeekFrom::Start(offset)).map_err(io)?;
            Ok(file)
        })();
        let version = self.version.clone();
        let chunk_bytes = self.chunk_bytes;
        let remaining = version.len().saturating_sub(offset);
        Box::pin(stream::unfold(Some((opened, remaining)), move |state| {
            let version = version.clone();
            async move {
                let (file, mut remaining) = state?;
                let result = (|| {
                    let mut file = file?;
                    // The extra byte detects append, including after the last
                    // data chunk. Every failure terminates with an error item.
                    let mut bytes = vec![0; chunk_bytes.min(remaining as usize + 1)];
                    let n = loop {
                        match file.read(&mut bytes) {
                            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                            other => break other.map_err(io)?,
                        }
                    };
                    if n as u64 > remaining {
                        return Err(changed());
                    }
                    if n == 0 {
                        if remaining != 0 || !same_version(&version, &file.metadata().map_err(io)?)
                        {
                            return Err(changed());
                        }
                        return Ok(None);
                    }
                    // A range consumer may stop before EOF. Check every chunk
                    // so it cannot silently join versions in a partial read.
                    if !same_version(&version, &file.metadata().map_err(io)?) {
                        return Err(changed());
                    }
                    remaining -= n as u64;
                    bytes.truncate(n);
                    Ok(Some((bytes.into(), file)))
                })();
                match result {
                    Ok(Some((bytes, file))) => Some((Ok(bytes), Some((Ok(file), remaining)))),
                    Ok(None) => None,
                    Err(error) => Some((Err(error), None)),
                }
            }
        }))
    }
}

impl Replay for SegmentBody {
    fn open(&self) -> ByteStream {
        self.reader(0)
    }

    fn open_at(&self, offset: u64) -> Option<ByteStream> {
        Some(self.reader(offset))
    }

    fn len_hint(&self) -> Option<u64> {
        Some(self.version.len())
    }

    fn validator(&self) -> Option<ContentId> {
        Some(self.validator)
    }
}

impl From<SegmentBody> for Body {
    fn from(body: SegmentBody) -> Self {
        Body::replay(body)
    }
}
