use std::io::BufReader;
use std::path::Path;

use anyhow::Result;
use indicatif::ProgressBar;

use super::entry::IndexEntry;
use super::format::IndexFormat;

impl super::IndexFile {
    /// Check whether the index file is sorted by hash prefix.
    pub fn check_sorted(&self, progress: Option<&ProgressBar>) -> Result<bool> {
        check_sorted(&self.path, progress)
    }
}

/// Verify that an index file is sorted by hash prefix.
///
/// Returns `true` if every entry's hash prefix is >= the previous entry's.
/// Returns `false` if any out-of-order pair is found.
pub fn check_sorted(index_path: &Path, progress: Option<&ProgressBar>) -> Result<bool> {
    let mut file = std::fs::File::open(index_path)?;
    let file_size = file.metadata()?.len();

    if file_size == 0 {
        return Ok(true);
    }

    let format = IndexFormat::detect_reader(&mut file, file_size)?;
    let num_entries = format.entry_count_for_size(file_size)?;
    if num_entries == 0 {
        return Ok(true);
    }
    if let Some(pb) = progress {
        pb.set_length(num_entries);
    }

    let mut reader = BufReader::new(file);
    let mut prev = IndexEntry::read_from_format(&mut reader, format)?;

    for i in 1..num_entries {
        let current = IndexEntry::read_from_format(&mut reader, format)?;
        if current.compare_prefix(&prev) == std::cmp::Ordering::Less {
            return Ok(false);
        }
        prev = current;

        if let Some(pb) = progress {
            if i % 10_000_000 == 0 {
                pb.set_position(i);
            }
        }
    }

    if let Some(pb) = progress {
        pb.set_position(num_entries);
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::IndexEntry;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_empty_file_is_sorted() {
        let f = NamedTempFile::new().expect("temp file");
        assert!(
            check_sorted(f.path(), None).expect("check"),
            "empty file should be sorted"
        );
    }

    #[test]
    fn test_single_entry_is_sorted() {
        let mut f = NamedTempFile::new().expect("temp file");
        let entry = IndexEntry::new([0xAA; 8], 0);
        entry.write_to(&mut f).expect("write");
        f.flush().expect("flush");
        assert!(check_sorted(f.path(), None).expect("check"));
    }

    #[test]
    fn test_sorted_entries() {
        let mut f = NamedTempFile::new().expect("temp file");
        IndexEntry::new([0x00; 8], 0)
            .write_to(&mut f)
            .expect("write");
        IndexEntry::new([0x01; 8], 14)
            .write_to(&mut f)
            .expect("write");
        IndexEntry::new([0xFF; 8], 28)
            .write_to(&mut f)
            .expect("write");
        f.flush().expect("flush");
        assert!(check_sorted(f.path(), None).expect("check"));
    }

    #[test]
    fn test_unsorted_entries() {
        let mut f = NamedTempFile::new().expect("temp file");
        IndexEntry::new([0xFF; 8], 0)
            .write_to(&mut f)
            .expect("write");
        IndexEntry::new([0x00; 8], 14)
            .write_to(&mut f)
            .expect("write");
        f.flush().expect("flush");
        assert!(
            !check_sorted(f.path(), None).expect("check"),
            "should detect unsorted"
        );
    }

    #[test]
    fn test_equal_entries_are_sorted() {
        let mut f = NamedTempFile::new().expect("temp file");
        IndexEntry::new([0xAA; 8], 0)
            .write_to(&mut f)
            .expect("write");
        IndexEntry::new([0xAA; 8], 14)
            .write_to(&mut f)
            .expect("write");
        f.flush().expect("flush");
        assert!(
            check_sorted(f.path(), None).expect("check"),
            "equal entries should be sorted"
        );
    }
}
