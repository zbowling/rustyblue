//! HCI Socket implementation for Bluetooth communication
//!
//! This module provides a wrapper around the raw HCI socket interface,
//! allowing for communication with Bluetooth controllers.

use crate::error::HciError;
use crate::hci::packet::{HciCommand, HciEvent};
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::Duration;

// Bluetooth socket constants
const AF_BLUETOOTH: i32 = 31;
const BTPROTO_HCI: i32 = 1;
const HCI_CHANNEL_RAW: i32 = 0;
const HCI_EVENT_PKT: u8 = 0x04;

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
    /// Gets the raw file descriptor for the socket
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd
    }

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
        let fd = unsafe { libc::socket(AF_BLUETOOTH, libc::SOCK_RAW, BTPROTO_HCI) };

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

    /// Read an HCI event from the socket
    pub fn read_event(&self) -> Result<HciEvent, HciError> {
        let mut buffer = [0u8; 258]; // Max HCI event packet size

        // Read packet type and header
        let bytes_read = unsafe {
            libc::read(
                self.fd,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
            )
        };

        if bytes_read < 0 {
            return Err(HciError::ReceiveError(std::io::Error::last_os_error()));
        }

        if bytes_read < 3 || buffer[0] != HCI_EVENT_PKT {
            return Err(HciError::InvalidPacketFormat);
        }

        // Parse event
        match HciEvent::parse(&buffer[1..bytes_read as usize]) {
            Some(event) => Ok(event),
            None => Err(HciError::InvalidPacketFormat),
        }
    }

    /// Read an HCI event from the socket with a timeout
    pub fn read_event_timeout(&self, timeout: Option<Duration>) -> Result<HciEvent, HciError> {
        if let Some(timeout) = timeout {
            // Set up the fd_set for select()
            let mut read_fds: libc::fd_set = unsafe { std::mem::zeroed() };
            unsafe {
                libc::FD_ZERO(&mut read_fds);
                libc::FD_SET(self.fd, &mut read_fds);
            }

            // Set up the timeout
            let mut timeout_val = libc::timeval {
                tv_sec: timeout.as_secs() as libc::time_t,
                tv_usec: timeout.subsec_micros() as libc::suseconds_t,
            };

            // Wait for data to be available
            let result = unsafe {
                libc::select(
                    self.fd + 1,
                    &mut read_fds,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut timeout_val,
                )
            };

            if result < 0 {
                return Err(HciError::ReceiveError(std::io::Error::last_os_error()));
            }

            if result == 0 {
                return Err(HciError::ReceiveError(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Timed out waiting for HCI event",
                )));
            }
        }

        // Read the event
        self.read_event()
    }

    /// Sends an HCI command to the controller
    pub fn send_command(&self, command: &HciCommand) -> Result<(), HciError> {
        let packet = command.to_packet();
        match unsafe {
            libc::write(
                self.fd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
            )
        } {
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
