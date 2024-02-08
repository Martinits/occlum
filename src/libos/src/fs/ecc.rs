use super::*;
use alloc::sync::*;
use eccfs::blk2byte;
pub use eccfs::FSMode;
use eccfs::BLK_SZ;
use rcore_fs::*;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirEntryExt, FileExt, FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{SgxMutex as Mutex, SgxMutexGuard as MutexGuard};
use std::untrusted::fs;
use std::untrusted::path::PathEx;

pub use eccfs::crypto::{KeyEntry, KEY_ENTRY_SZ};

macro_rules! mutex_lock {
    ($mu: expr) => {
        $mu.lock().map_err(|_| eccfs::FsError::MutexError)?
    };
}

macro_rules! io_try {
    ($e: expr) => {
        $e.map_err(|_| eccfs::FsError::IOError)?
    };
}

pub fn parse_ke(s: &str) -> Result<KeyEntry> {
    if s.len() != KEY_ENTRY_SZ * 2 {
        return_errno!(EINVAL, "The length or format of KeyEntry string is invalid");
    }

    let mut ke = [0u8; KEY_ENTRY_SZ];
    for i in (0..KEY_ENTRY_SZ) {
        ke[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|e| errno!(e))?;
    }
    Ok(ke)
}

fn eccfs_error_to_rcore_fs_error(from: eccfs::FsError) -> rcore_fs::vfs::FsError {
    use rcore_fs::vfs::FsError;
    match from {
        eccfs::FsError::IOError => FsError::Busy,
        eccfs::FsError::DirectoryNotEmpty => FsError::DirNotEmpty,
        eccfs::FsError::InvalidData => FsError::InvalidParam,
        eccfs::FsError::InvalidParameter => FsError::InvalidParam,
        eccfs::FsError::NotFound => FsError::EntryNotFound,
        eccfs::FsError::NotADirectory => FsError::NotDir,
        eccfs::FsError::IsADirectory => FsError::IsDir,
        eccfs::FsError::AlreadyExists => FsError::EntryExist,
        eccfs::FsError::PermissionDenied => FsError::PermError,
        eccfs::FsError::UnexpectedEof => FsError::InvalidParam,
        eccfs::FsError::NotSupported => FsError::NotSupported,
        eccfs::FsError::CryptoError => FsError::InvalidParam,
        eccfs::FsError::IntegrityCheckError => FsError::WrongFs,
        eccfs::FsError::CacheIsFull => FsError::Busy,
        eccfs::FsError::RwLockError => FsError::Busy,
        eccfs::FsError::MutexError => FsError::Busy,
        eccfs::FsError::CacheNeedHint => FsError::NotSupported,
        eccfs::FsError::IncompatibleMetadata => FsError::WrongFs,
        eccfs::FsError::SuperBlockCheckFailed => FsError::WrongFs,
        eccfs::FsError::UnknownError => FsError::NotSupported,
    }
}

macro_rules! eccfs_try {
    ($e: expr) => {
        $e.map_err(|e| eccfs_error_to_rcore_fs_error(e))?
    };
}

macro_rules! eccfs_err_to_occlum {
    ($e: expr) => {
        $e.map_err(|e| {
            let eno = Into::<libc::c_int>::into(e) as u8;
            if eno > EHWPOISON as u8 {
                EINVAL
            } else {
                (eno as u32).into()
            }
        })?
    };
}

struct EccFSTimeProvider;

impl eccfs::TimeSource for EccFSTimeProvider {
    fn now(&self) -> u32 {
        let time = time::do_gettimeofday();
        time.sec() as u32
    }
}

// for ECC_RWFS
struct EccFSDevice {
    dir: PathBuf, // full path
}

impl eccfs::Device for EccFSDevice {
    fn nr_storage(&self) -> eccfs::FsResult<usize> {
        if !io_try!(fs::metadata(&self.dir)).is_dir() {
            return Err(eccfs::FsError::NotADirectory);
        }
        Ok(io_try!(fs::read_dir(&self.dir)).count())
    }

    fn open_rw_storage(&self, path: &str) -> eccfs::FsResult<Arc<dyn eccfs::RWStorage>> {
        let mut p = self.dir.clone();
        p.push(path);

        let f = io_try!(fs::OpenOptions::new().read(true).write(true).open(&p));
        Ok(Arc::new(EccFSStorage { f: Mutex::new(f) }))
    }

    fn create_rw_storage(&self, path: &str) -> eccfs::FsResult<Arc<dyn eccfs::RWStorage>> {
        let mut p = self.dir.clone();
        p.push(path);

        let f = io_try!(fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&p));
        Ok(Arc::new(EccFSStorage { f: Mutex::new(f) }))
    }

    fn get_storage_len(&self, path: &str) -> eccfs::FsResult<u64> {
        let mut p = self.dir.clone();
        p.push(path);

        Ok(io_try!(fs::metadata(&p)).len())
    }

    fn remove_storage(&self, path: &str) -> eccfs::FsResult<()> {
        let mut p = self.dir.clone();
        p.push(path);

        io_try!(fs::remove_file(&p));
        Ok(())
    }
}

struct EccFSStorage {
    f: Mutex<fs::File>,
}

impl eccfs::ROStorage for EccFSStorage {
    fn read_blk_to(&self, pos: u64, to: &mut eccfs::Block) -> eccfs::FsResult<()> {
        io_try!(mutex_lock!(self.f).read_exact_at(to, blk2byte!(pos)));
        Ok(())
    }
}

impl eccfs::RWStorage for EccFSStorage {
    fn get_len(&self) -> eccfs::FsResult<u64> {
        Ok(io_try!(mutex_lock!(self.f).seek(SeekFrom::End(0))))
    }

    fn set_len(&self, nr_blk: u64) -> eccfs::FsResult<()> {
        let len = blk2byte!(nr_blk);
        io_try!(mutex_lock!(self.f).set_len(len));
        Ok(())
    }

    fn write_blk(&self, pos: u64, from: &eccfs::Block) -> eccfs::FsResult<()> {
        let cur_len = self.get_len()?;
        let offset = blk2byte!(pos);
        assert!(offset < cur_len);

        Ok(io_try!(mutex_lock!(self.f).write_all_at(from, offset)))
    }
}

pub struct EccFS {
    fs: Arc<dyn eccfs::FileSystem>,
    writable: bool,
    self_ptr: Weak<EccFS>,
}

impl EccFS {
    pub fn new(
        path: &PathBuf,
        writable: bool,
        mode: FSMode,
        cache_size: Option<u64>,
    ) -> Result<Arc<Self>> {
        debug!("creating eccfs {}", path.display());
        let fs = if writable {
            let device = EccFSDevice { dir: path.clone() };
            let fs = eccfs_err_to_occlum!(eccfs::rw::RWFS::new(
                false,
                mode,
                None,
                0,
                Arc::new(device),
                &EccFSTimeProvider,
            ));
            Arc::new(fs) as Arc<dyn eccfs::FileSystem>
        } else {
            let store = EccFSStorage {
                f: Mutex::new(fs::File::open(path).map_err(|_| errno!(EIO))?),
            };
            let fs = eccfs_err_to_occlum!(eccfs::ro::ROFS::new(
                mode,
                cache_size.unwrap_or(0) as usize,
                Some(0),
                0,
                Arc::new(store),
            ));
            Arc::new(fs) as Arc<dyn eccfs::FileSystem>
        };

        let mut ret = Self {
            fs,
            writable,
            self_ptr: Weak::default(),
        };

        let fs = Arc::new(ret);
        let weak = Arc::downgrade(&fs);
        let ptr = Arc::into_raw(fs) as *mut Self;
        unsafe {
            (*ptr).self_ptr = weak;
        }
        Ok(unsafe { Arc::from_raw(ptr) })
    }

    pub fn new_inode(&self, iid: eccfs::InodeID) -> Arc<EccInode> {
        Arc::new(EccInode {
            iid,
            fs: self.fs.clone(),
            rcore_fs: self.self_ptr.upgrade().unwrap(),
        })
    }
}

impl FileSystem for EccFS {
    fn sync(&self) -> vfs::Result<()> {
        eccfs_try!(self.fs.fsync());
        Ok(())
    }

    fn root_inode(&self) -> Arc<dyn vfs::INode> {
        self.new_inode(eccfs::ROOT_INODE_ID)
    }

    fn root_mac(&self) -> vfs::FsMac {
        Default::default()
    }

    fn info(&self) -> vfs::FsInfo {
        let i = self.fs.finfo().unwrap();
        vfs::FsInfo {
            magic: i.magic as usize,
            bsize: i.bsize,
            frsize: i.frsize,
            blocks: i.blocks,
            bfree: i.bfree,
            bavail: i.bavail,
            files: i.files,
            ffree: i.ffree,
            namemax: i.namemax,
        }
    }
}

pub struct EccInode {
    iid: eccfs::InodeID,
    fs: Arc<dyn eccfs::FileSystem>,
    rcore_fs: Arc<EccFS>,
}

fn rcore_fs_tp_to_eccfs_tp(from: vfs::FileType) -> vfs::Result<eccfs::FileType> {
    let tp = match from {
        vfs::FileType::File => eccfs::FileType::Reg,
        vfs::FileType::Dir => eccfs::FileType::Dir,
        vfs::FileType::SymLink => eccfs::FileType::Lnk,
        _ => return Err(vfs::FsError::NotSupported),
    };
    Ok(tp)
}

fn eccfs_tp_to_rcore_fs_tp(from: eccfs::FileType) -> vfs::FileType {
    match from {
        eccfs::FileType::Reg => vfs::FileType::File,
        eccfs::FileType::Dir => vfs::FileType::Dir,
        eccfs::FileType::Lnk => vfs::FileType::SymLink,
    }
}

impl INode for EccInode {
    fn read_at(&self, offset: usize, buf: &mut [u8]) -> vfs::Result<usize> {
        debug!("eccfs: read_at {offset}");
        let read = eccfs_try!(self.fs.iread(self.iid, offset, buf));
        Ok(read)
    }

    fn write_at(&self, offset: usize, buf: &[u8]) -> vfs::Result<usize> {
        debug!("eccfs: write_at {offset}");
        let written = eccfs_try!(self.fs.iwrite(self.iid, offset, buf));
        Ok(written)
    }

    fn metadata(&self) -> vfs::Result<vfs::Metadata> {
        debug!("eccfs: metadata");
        let meta = eccfs_try!(self.fs.get_meta(self.iid));
        Ok(vfs::Metadata {
            dev: 0,
            inode: self.iid as usize,
            size: meta.size as usize,
            blk_size: BLK_SZ,
            blocks: (meta.size as usize + BLK_SZ - 1) / BLK_SZ,
            atime: Timespec {
                sec: meta.atime as i64,
                nsec: 0,
            },
            mtime: Timespec {
                sec: meta.mtime as i64,
                nsec: 0,
            },
            ctime: Timespec {
                sec: meta.ctime as i64,
                nsec: 0,
            },
            type_: eccfs_tp_to_rcore_fs_tp(meta.ftype),
            mode: meta.perm.bits(),
            nlinks: meta.nlinks as usize,
            uid: meta.uid as usize,
            gid: meta.gid as usize,
            rdev: 0,
        })
    }

    fn set_metadata(&self, metadata: &vfs::Metadata) -> vfs::Result<()> {
        debug!("eccfs: set_metadata");
        let mut set_meta = Vec::new();
        set_meta.push(eccfs::SetMetadata::Uid(metadata.uid as u32));
        set_meta.push(eccfs::SetMetadata::Gid(metadata.gid as u32));
        set_meta.push(eccfs::SetMetadata::Size(metadata.size));
        set_meta.push(eccfs::SetMetadata::Atime(metadata.atime.sec as u32));
        set_meta.push(eccfs::SetMetadata::Ctime(metadata.ctime.sec as u32));
        set_meta.push(eccfs::SetMetadata::Mtime(metadata.mtime.sec as u32));
        set_meta.push(eccfs::SetMetadata::Permission(
            eccfs::FilePerm::from_bits(metadata.mode).unwrap(),
        ));

        for sm in set_meta {
            eccfs_try!(self.fs.set_meta(self.iid, sm));
        }
        Ok(())
    }

    fn sync_all(&self) -> vfs::Result<()> {
        debug!("eccfs: sync_all");
        eccfs_try!(self.fs.isync_data(self.iid));
        eccfs_try!(self.fs.isync_meta(self.iid));
        Ok(())
    }

    fn sync_data(&self) -> vfs::Result<()> {
        debug!("eccfs: sync_data");
        eccfs_try!(self.fs.isync_data(self.iid));
        Ok(())
    }

    fn fallocate(&self, mode: &vfs::FallocateMode, offset: usize, len: usize) -> vfs::Result<()> {
        debug!("eccfs: fallocate");
        let ecc_mode = match mode {
            vfs::FallocateMode::Allocate(flag) => {
                if flag.bits() == 0 {
                    return Err(vfs::FsError::NotSupported);
                }
                eccfs::FallocateMode::Alloc
            }
            vfs::FallocateMode::ZeroRange => eccfs::FallocateMode::ZeroRange,
            _ => return Err(vfs::FsError::NotSupported),
        };
        eccfs_try!(self.fs.fallocate(self.iid, ecc_mode, offset, len));
        Ok(())
    }

    fn resize(&self, len: usize) -> vfs::Result<()> {
        debug!("eccfs: resize");
        eccfs_try!(self.fs.set_meta(self.iid, eccfs::SetMetadata::Size(len)));
        Ok(())
    }

    fn create(
        &self,
        name: &str,
        type_: vfs::FileType,
        mode: u16,
    ) -> vfs::Result<Arc<dyn vfs::INode>> {
        debug!("eccfs: create");
        let meta = eccfs_try!(self.fs.get_meta(self.iid));
        let tp = rcore_fs_tp_to_eccfs_tp(type_)?;
        let iid = eccfs_try!(self.fs.create(
            self.iid,
            name,
            tp,
            meta.uid,
            meta.gid,
            eccfs::FilePerm::from_bits(mode).unwrap(),
        ));
        Ok(self.rcore_fs.new_inode(iid))
    }

    fn unlink(&self, name: &str) -> vfs::Result<()> {
        debug!("eccfs: unlink");
        eccfs_try!(self.fs.unlink(self.iid, name));
        Ok(())
    }

    fn link(&self, name: &str, other: &Arc<dyn vfs::INode>) -> vfs::Result<()> {
        debug!("eccfs: link");
        let linkto = other.metadata()?.inode as eccfs::InodeID;
        eccfs_try!(self.fs.link(self.iid, name, linkto));
        Ok(())
    }

    fn move_(
        &self,
        old_name: &str,
        target: &Arc<dyn vfs::INode>,
        new_name: &str,
    ) -> vfs::Result<()> {
        debug!("eccfs: move_");
        let to = target.metadata()?.inode as eccfs::InodeID;
        eccfs_try!(self.fs.rename(self.iid, old_name, to, new_name));
        Ok(())
    }

    fn find(&self, name: &str) -> vfs::Result<Arc<dyn vfs::INode>> {
        debug!("eccfs: find");
        if let Some(iid) = eccfs_try!(self.fs.lookup(self.iid, name)) {
            Ok(self.rcore_fs.new_inode(iid))
        } else {
            Err(vfs::FsError::EntryNotFound)
        }
    }

    fn get_entry(&self, id: usize) -> vfs::Result<String> {
        debug!("eccfs: get_entry");
        Ok(eccfs_try!(self.fs.next_entry(self.iid, id)).unwrap().1)
    }

    fn iterate_entries(&self, ctx: &mut vfs::DirentWriterContext) -> vfs::Result<usize> {
        debug!("eccfs: iterate_entries");
        loop {
            let offset = ctx.pos();
            if let Some((iid, name, tp)) = eccfs_try!(self.fs.next_entry(self.iid, offset)) {
                if let Err(e) = ctx.write_entry(&name, iid, eccfs_tp_to_rcore_fs_tp(tp)) {
                    if ctx.written_len() == 0 {
                        return Err(e);
                    } else {
                        break;
                    }
                };
            } else {
                break;
            }
        }
        Ok(ctx.written_len())
    }

    fn fs(&self) -> Arc<dyn vfs::FileSystem> {
        self.rcore_fs.clone()
    }

    fn as_any_ref(&self) -> &dyn Any {
        self
    }
}
