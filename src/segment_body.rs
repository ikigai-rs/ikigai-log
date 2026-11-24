//! File-backed raw segment bodies with live prefix and sealed version pins.

use std::fs::{File, Metadata};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use futures_util::stream;
use ikigai_core::{Body, ByteStream, ContentHasher, ContentId, Error, Replay, Result};

use crate::line::{Header, Line};
use crate::segments::MAX_SEGMENT_BYTES;
use crate::Vocabulary;

const CHUNK_BYTES: usize = 64 * 1024;

pub(crate) struct SegmentBody {
    path: PathBuf,
    pin: Pin,
    length: u64,
    validator: ContentId,
    chunk_bytes: usize,
}

#[derive(Clone)]
enum Pin {
    // Keep the original handle alive so the file ID cannot be reused.
    Live(Arc<same_file::Handle>),
    Sealed(Metadata),
}

impl Pin {
    fn check(&self, file: &File, path: &Path, length: u64) -> Result<()> {
        let metadata = file.metadata().map_err(io)?;
        let matches = match self {
            Self::Live(identity) => {
                // Check the path as well as the open file so a replacement during
                // a read is refused even while the old descriptor remains valid.
                // ambient: fs: checks the identity of the log's own segment path
                metadata.len() >= length
                    && same_file::Handle::from_path(path).is_ok_and(|named| named == **identity)
            }
            Self::Sealed(version) => same_version(version, &metadata),
        };
        if matches {
            Ok(())
        } else {
            Err(changed())
        }
    }
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
        is_open: impl FnOnce() -> bool,
    ) -> Result<(Self, bool)> {
        // ambient: fs: opens one of the log's own segment files for a streamed body
        #[allow(clippy::disallowed_methods)]
        let file = File::open(path).map_err(io)?;
        let version = file.metadata().map_err(io)?;
        let length = version.len();
        if length > MAX_SEGMENT_BYTES as u64 {
            return Err(over());
        }
        if memory_bytes == 0 {
            return Err(over());
        }
        let chunk_bytes = CHUNK_BYTES.min((memory_bytes / 4).max(1));
        let mut reader = BufReader::with_capacity(chunk_bytes, file.take(length));
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
        if seen as u64 != length {
            return Err(changed());
        }
        let finished = ended && sealed_after && !after_end && !is_open();
        let file = reader.into_inner().into_inner();
        let pin = if finished {
            Pin::Sealed(version)
        } else {
            Pin::Live(Arc::new(
                same_file::Handle::from_file(file.try_clone().map_err(io)?).map_err(io)?,
            ))
        };
        pin.check(&file, path, length)?;
        Ok((
            Self {
                path: path.into(),
                pin,
                length,
                validator: hasher.finish(),
                chunk_bytes,
            },
            finished,
        ))
    }

    fn reader(&self, offset: u64) -> ByteStream {
        let opened = (|| {
            // ambient: fs: reopens the pinned segment file, refused below if it changed
            #[allow(clippy::disallowed_methods)]
            let mut file = File::open(&self.path).map_err(|_| changed())?;
            if let Pin::Live(identity) = &self.pin {
                let opened =
                    same_file::Handle::from_file(file.try_clone().map_err(io)?).map_err(io)?;
                if opened != **identity {
                    return Err(changed());
                }
            }
            self.pin.check(&file, &self.path, self.length)?;
            file.seek(SeekFrom::Start(offset)).map_err(io)?;
            Ok(file)
        })();
        let pin = self.pin.clone();
        let path = Arc::new(self.path.clone());
        let length = self.length;
        let sentinel = usize::from(matches!(pin, Pin::Sealed(_)));
        let chunk_bytes = self.chunk_bytes;
        let remaining = length.saturating_sub(offset);
        Box::pin(stream::unfold(Some((opened, remaining)), move |state| {
            let pin = pin.clone();
            let path = path.clone();
            async move {
                let (file, mut remaining) = state?;
                let result = (|| {
                    let mut file = file?;
                    // Only sealed readers probe beyond the pinned length.
                    let mut bytes = vec![0; chunk_bytes.min(remaining as usize + sentinel)];
                    let n = loop {
                        match file.read(&mut bytes) {
                            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                            other => break other.map_err(io)?,
                        }
                    };
                    if n as u64 > remaining || (n == 0 && remaining != 0) {
                        return Err(changed());
                    }
                    // A range consumer may stop before EOF, so check every chunk.
                    pin.check(&file, &path, length)?;
                    if n == 0 {
                        return Ok(None);
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
        Some(self.length)
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
