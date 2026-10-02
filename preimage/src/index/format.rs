use std::io::{Read, Seek, SeekFrom, Write};

use anyhow::{bail, Result};

pub const V2_MAGIC: &[u8; 16] = b"PREIMAGE-IDX2\0\0\0";
pub const V2_VERSION: u32 = 2;
pub const V2_HEADER_SIZE: u64 = 24;
pub const V1_ENTRY_SIZE: usize = 14;
pub const V2_ENTRY_SIZE: usize = 13;
pub const V1_POSITION_LEN: usize = 6;
pub const V2_POSITION_LEN: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexFormat {
    LegacyV1,
    CompactV2,
}

impl IndexFormat {
    pub const fn entry_size(self) -> usize {
        match self {
            Self::LegacyV1 => V1_ENTRY_SIZE,
            Self::CompactV2 => V2_ENTRY_SIZE,
        }
    }

    pub const fn position_len(self) -> usize {
        match self {
            Self::LegacyV1 => V1_POSITION_LEN,
            Self::CompactV2 => V2_POSITION_LEN,
        }
    }

    pub const fn data_offset(self) -> u64 {
        match self {
            Self::LegacyV1 => 0,
            Self::CompactV2 => V2_HEADER_SIZE,
        }
    }

    pub const fn max_position(self) -> u64 {
        match self {
            Self::LegacyV1 => 0xFFFF_FFFF_FFFF,
            Self::CompactV2 => 0xFF_FFFF_FFFF,
        }
    }

    pub fn write_header(self, writer: &mut impl Write) -> std::io::Result<()> {
        if self == Self::CompactV2 {
            writer.write_all(V2_MAGIC)?;
            writer.write_all(&V2_VERSION.to_le_bytes())?;
            writer.write_all(&(V2_ENTRY_SIZE as u32).to_le_bytes())?;
        }
        Ok(())
    }

    pub fn detect_reader(reader: &mut (impl Read + Seek), file_size: u64) -> Result<Self> {
        if file_size < V2_MAGIC.len() as u64 {
            reader.seek(SeekFrom::Start(0))?;
            return Ok(Self::LegacyV1);
        }

        let mut magic = [0u8; 16];
        reader.read_exact(&mut magic)?;
        if &magic != V2_MAGIC {
            reader.seek(SeekFrom::Start(0))?;
            return Ok(Self::LegacyV1);
        }

        if file_size < V2_HEADER_SIZE {
            bail!("IDX2 header is truncated");
        }

        let mut version = [0u8; 4];
        let mut entry_size = [0u8; 4];
        reader.read_exact(&mut version)?;
        reader.read_exact(&mut entry_size)?;

        let version = u32::from_le_bytes(version);
        if version != V2_VERSION {
            bail!("unsupported IDX2 version {version}");
        }

        let entry_size = u32::from_le_bytes(entry_size) as usize;
        if entry_size != V2_ENTRY_SIZE {
            bail!(
                "IDX2 header declares entry size {entry_size}, expected {V2_ENTRY_SIZE}"
            );
        }

        reader.seek(SeekFrom::Start(V2_HEADER_SIZE))?;
        Ok(Self::CompactV2)
    }

    pub fn detect_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < V2_MAGIC.len() || &bytes[..V2_MAGIC.len()] != V2_MAGIC {
            return Ok(Self::LegacyV1);
        }
        if bytes.len() < V2_HEADER_SIZE as usize {
            bail!("IDX2 header is truncated");
        }

        let version = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
        if version != V2_VERSION {
            bail!("unsupported IDX2 version {version}");
        }
        let entry_size = u32::from_le_bytes(bytes[20..24].try_into().unwrap()) as usize;
        if entry_size != V2_ENTRY_SIZE {
            bail!(
                "IDX2 header declares entry size {entry_size}, expected {V2_ENTRY_SIZE}"
            );
        }
        Ok(Self::CompactV2)
    }

    pub fn entry_count_for_size(self, file_size: u64) -> Result<u64> {
        let data_len = file_size
            .checked_sub(self.data_offset())
            .ok_or_else(|| anyhow::anyhow!("index file is shorter than its header"))?;
        if data_len % self.entry_size() as u64 != 0 {
            bail!(
                "index data size {} is not a multiple of entry size {}",
                data_len,
                self.entry_size()
            );
        }
        Ok(data_len / self.entry_size() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn detects_legacy_without_magic() {
        let bytes = vec![0u8; V1_ENTRY_SIZE * 2];
        let mut cursor = Cursor::new(bytes.clone());
        assert_eq!(
            IndexFormat::detect_reader(&mut cursor, bytes.len() as u64).unwrap(),
            IndexFormat::LegacyV1
        );
        assert_eq!(cursor.position(), 0);
    }

    #[test]
    fn writes_and_detects_v2_header() {
        let mut bytes = Vec::new();
        IndexFormat::CompactV2.write_header(&mut bytes).unwrap();
        assert_eq!(bytes.len(), V2_HEADER_SIZE as usize);
        let mut cursor = Cursor::new(bytes.clone());
        assert_eq!(
            IndexFormat::detect_reader(&mut cursor, bytes.len() as u64).unwrap(),
            IndexFormat::CompactV2
        );
        assert_eq!(cursor.position(), V2_HEADER_SIZE);
        assert_eq!(
            IndexFormat::detect_bytes(&bytes).unwrap(),
            IndexFormat::CompactV2
        );
    }
}
