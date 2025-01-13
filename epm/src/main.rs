use std::os::unix::net::{UnixListener, UnixStream};
use std::io::{Read, Write};
use std::sync::Mutex;
use log::info;
use std::path::PathBuf;
use lazy_static::lazy_static;
use std::os::fd::{RawFd, AsRawFd};
use std::io::{IoSlice, IoSliceMut};
use nix::sys::socket::{self, ControlMessage, MsgFlags, ControlMessageOwned};
use std::net::Shutdown;
use nix::cmsg_space;
use nix::unistd::close;
use std::mem::size_of;

const EPM_SOCK_PATH: &str = "/run/epm/epm.sock";
const EPM_DIR: &str = "/run/epm";

#[repr(C)]
#[derive(Default, Debug, Clone)]
struct EnclaveInfoHdr {
    id: u32,
    nr_range: u32,
}

#[repr(C)]
#[derive(Default, Debug, Clone)]
struct EnclaveRange {
    addr: u64,
    size: u64,
    prot: u32,
    flags: u32,
}

#[derive(Default, Debug, Clone)]
struct EnclaveInfo {
    id: u32,
    efd: RawFd,
    ranges: Vec<EnclaveRange>,
}

impl Into<Vec<u8>> for &EnclaveInfo {
    fn into(self) -> Vec<u8> {
        let mut buf = vec![
            0u8;
            size_of::<EnclaveInfoHdr>()
                + size_of::<EnclaveRange>() * self.ranges.len()
        ];

        unsafe {
            let hdr = (buf.as_mut_ptr() as *mut EnclaveInfoHdr).as_mut().unwrap();
            hdr.nr_range = self.ranges.len() as u32;
            hdr.id = self.id;

            let ers = std::slice::from_raw_parts_mut(
                buf[size_of::<EnclaveInfoHdr>()..].as_mut_ptr() as *mut EnclaveRange,
                self.ranges.len(),
            );
            ers.clone_from_slice(self.ranges.as_slice());
        }

        buf
    }
}

lazy_static!{
    static ref EPOOL: Mutex<Vec<EnclaveInfo>> = Mutex::new(Vec::new());
    static ref NULL_EINFO: EnclaveInfoHdr = EnclaveInfoHdr {
        nr_range: 0,
        ..Default::default()
    };
}

fn get_eid_path(id: u32) -> PathBuf {
    let mut pb = PathBuf::from(EPM_DIR);
    pb.push(format!("{:08x}", id));
    pb
}

fn send_fd(efd: RawFd, id: u32) {
    let fd_sock_path = get_eid_path(id);
    let stream = UnixStream::connect(&fd_sock_path).unwrap();

    let iov = [IoSlice::new(b" ")];
    let fds = [efd];
    let cmsg = ControlMessage::ScmRights(&fds);
    socket::sendmsg::<()>(stream.as_raw_fd(), &iov, &[cmsg], MsgFlags::empty(), None).unwrap();

    stream.shutdown(Shutdown::Write).unwrap();

    std::fs::remove_file(&fd_sock_path).unwrap();
}

fn recv_fd(id: u32) -> RawFd {
    let stream = UnixListener::bind(get_eid_path(id)).unwrap();

    let mut buf = [0u8; 100];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsg = cmsg_space!([RawFd; 1]);
    let res = socket::recvmsg::<()>(stream.as_raw_fd(), &mut iov, Some(&mut cmsg), MsgFlags::empty()).unwrap();
    let fd = if let ControlMessageOwned::ScmRights(fd) = res.cmsgs().unwrap().next().unwrap() {
        assert_eq!(fd.len(), 1);
        RawFd::from(fd[0])
    } else {
        RawFd::from(-1)
    };

    close(stream.as_raw_fd()).unwrap();

    fd
}

fn send_empty_hdr(mut stream: UnixStream) {
    let empty_hdr = NULL_EINFO.clone();
    stream.write_all(
        unsafe {
            std::slice::from_raw_parts(
                &empty_hdr as *const EnclaveInfoHdr as *const u8,
                size_of::<EnclaveInfoHdr>(),
            )
        }
    ).unwrap();
}

fn handle_get(mut stream: UnixStream) {
    info!("Handle Get");

    if EPOOL.lock().unwrap().is_empty() {
        info!("Pool is empty, return empty header");
        return send_empty_hdr(stream);
    }

    let einfo = EPOOL.lock().unwrap().pop().unwrap();

    let efd = einfo.efd;

    info!("Sending EnclaveInfo, nr_range={}", einfo.ranges.len());
    stream.write_all(Into::<Vec<u8>>::into(&einfo).as_slice()).unwrap();

    info!("Sending fd {}", efd);
    send_fd(efd, einfo.id);
}

fn handle_save(mut stream: UnixStream) {
    info!("Handle Save");

    let mut hdr = EnclaveInfoHdr::default();

    info!("Receiving header");
    stream.read_exact(
        unsafe {
            std::slice::from_raw_parts_mut(
                &mut hdr as *mut EnclaveInfoHdr as *mut u8,
                size_of::<EnclaveInfoHdr>(),
            )
        }
    ).unwrap();

    assert_ne!(hdr.nr_range, 0);
    info!("Received EnclaveInfo header, nr_range={}", hdr.nr_range);

    let mut ers = vec![EnclaveRange::default(); hdr.nr_range as usize];
    stream.read_exact(
        unsafe {
            std::slice::from_raw_parts_mut(
                ers.as_mut_ptr() as *mut u8,
                size_of::<EnclaveRange>() * hdr.nr_range as usize,
            )
        }
    ).unwrap();
    info!("Received EnclaveRanges");

    let efd = recv_fd(hdr.id);
    info!("Received fd {}", efd);

    EPOOL.lock().unwrap().push(EnclaveInfo {
        id: hdr.id,
        efd,
        ranges: ers,
    });
}

fn main() -> std::io::Result<()> {
    env_logger::builder().filter_level(log::LevelFilter::Info).init();

    let listener = UnixListener::bind(EPM_SOCK_PATH)?;
    info!("Server listening on {}", EPM_SOCK_PATH);

    for stream in listener.incoming() {
        if let Ok(mut stream) = stream {
            info!("Got Connected");

            let mut buffer = [0u8; 128];
            if stream.read_exact(&mut buffer[..1]).is_ok() {
                match std::str::from_utf8(&buffer[..1]) {
                    Ok("g") => handle_get(stream),
                    Ok("s") => handle_save(stream),
                    _ => info!("Invalid command!"),
                }
            } else {
                info!("Cannot read command byte, skip");
            }
        } else {
            info!("Receive error, exiting......");
            break;
        }
    }

    std::fs::remove_file(EPM_SOCK_PATH)?;
    Ok(())
}

