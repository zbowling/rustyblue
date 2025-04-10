//! HCI Socket implementation for Bluetooth communication
//!
//! This module provides a wrapper around the raw HCI socket interface,
//! allowing for communication with Bluetooth controllers.

use std::os::unix::io::{AsRawFd, RawFd};
use crate::hci::packet::HciCommand;
use crate::error::HciError;

// Bluetooth socket constants
const AF_BLUETOOTH: i32 = 31;
const BTPROTO_HCI: i32 = 1;
const HCI_CHANNEL_RAW: i32 = 0;

/// Represents an HCI socket
#[derive(Debug)]
pub struct HciSocket {
    fd: RawFd,
}

// Define the sockaddr_hci structure
#[repr(C)]
struct SockaddrHci {
    hci_family: libc::sa_family_t,
    hci_dev: u16,
    hci_channel: u16,
}

impl HciSocket {
    /// Opens a new HCI socket
    /// 
    /// # Arguments
    /// 
    /// * `dev_id` - The device ID to open (0 for the first device)
    /// 
    /// # Returns
    /// 
    /// A new `HciSocket` instance or an error if the socket could not be opened
    pub fn open(dev_id: u16) -> Result<Self, HciError> {
        // Open a raw HCI socket
        let fd = unsafe {
            libc::socket(
                AF_BLUETOOTH,
                libc::SOCK_RAW,
                BTPROTO_HCI,
            )
        };
        
        if fd < 0 {
            return Err(HciError::SocketError(std::io::Error::last_os_error()));
        }
        
        // Bind to the specified device
        let addr = SockaddrHci {
            hci_family: AF_BLUETOOTH as libc::sa_family_t,
            hci_dev: dev_id,
            hci_channel: HCI_CHANNEL_RAW as u16,
        };
        
        let result = unsafe {
            libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<SockaddrHci>() as libc::socklen_t,
            )
        };
        
        if result < 0 {
            unsafe { libc::close(fd) };
            return Err(HciError::BindError(std::io::Error::last_os_error()));
        }
        
        Ok(HciSocket { fd })
    }
    
    /// Gets the raw file descriptor for the socket
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd
    }

    /// Sends an HCI command to the controller
    pub fn send_command(&self, command: &HciCommand) -> Result<(), HciError> {
        let packet = command.to_packet();
        match unsafe { libc::write(self.fd, packet.as_ptr() as *const libc::c_void, packet.len()) } {
            -1 => Err(HciError::SendError(std::io::Error::last_os_error())),
            _ => Ok(()),
        }
    }
}

impl AsRawFd for HciSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for HciSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}
