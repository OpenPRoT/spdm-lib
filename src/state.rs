// Licensed under the Apache-2.0 license

use crate::{
    cert_store::PeerCertStore,
    protocol::{DeviceAlgorithms, DeviceCapabilities, SpdmVersion},
};

pub(crate) struct State<'a> {
    pub(crate) connection_info: ConnectionInfo,
    pub(crate) peer_cert_store: Option<&'a mut dyn PeerCertStore>,
}

impl<'a> Default for State<'a> {
    fn default() -> Self {
        Self::new(None)
    }
}

impl<'a> State<'a> {
    pub fn new(peer_cert_store: Option<&'a mut dyn PeerCertStore>) -> Self {
        Self {
            connection_info: ConnectionInfo::default(),
            peer_cert_store,
        }
    }

    pub fn reset(&mut self) {
        self.connection_info.reset();
    }
}

pub struct ConnectionInfo {
    version_number: SpdmVersion,
    state: ConnectionState,
    peer_algorithms: DeviceAlgorithms,
    peer_capabilities: DeviceCapabilities,
    multi_key_conn_rsp: bool,
}

impl Default for ConnectionInfo {
    fn default() -> Self {
        Self {
            version_number: SpdmVersion::default(),
            state: ConnectionState::NotStarted,
            peer_capabilities: DeviceCapabilities::default(),
            peer_algorithms: DeviceAlgorithms::default(),
            multi_key_conn_rsp: false,
        }
    }
}

impl ConnectionInfo {
    pub fn version_number(&self) -> SpdmVersion {
        self.version_number
    }

    pub(crate) fn set_version_number(&mut self, version_number: SpdmVersion) {
        self.version_number = version_number;
    }

    pub fn state(&self) -> ConnectionState {
        self.state
    }

    pub(crate) fn set_state(&mut self, state: ConnectionState) {
        self.state = state;
    }

    pub(crate) fn set_peer_capabilities(&mut self, peer_capabilities: DeviceCapabilities) {
        self.peer_capabilities = peer_capabilities;
    }

    pub fn peer_capabilities(&self) -> DeviceCapabilities {
        self.peer_capabilities
    }

    pub(crate) fn set_peer_algorithms(&mut self, peer_algorithms: DeviceAlgorithms) {
        self.peer_algorithms = peer_algorithms;
    }

    pub fn peer_algorithms(&self) -> &DeviceAlgorithms {
        &self.peer_algorithms
    }

    #[allow(dead_code)]
    pub(crate) fn set_multi_key_conn_rsp(&mut self, multi_key_conn_rsp: bool) {
        self.multi_key_conn_rsp = multi_key_conn_rsp;
    }

    pub fn multi_key_conn_rsp(&self) -> bool {
        self.multi_key_conn_rsp
    }

    fn reset(&mut self) {
        self.version_number = SpdmVersion::default();
        self.state = ConnectionState::NotStarted;
        self.peer_capabilities = DeviceCapabilities::default();
        self.peer_algorithms = DeviceAlgorithms::default();
    }
}

#[derive(Debug, Copy, Clone, PartialEq, PartialOrd)]
pub enum ConnectionState {
    NotStarted,
    AfterVersion,
    AfterCapabilities,
    AlgorithmsNegotiated,
    AfterDigest,
    /// Cert chain retrieval in process
    DuringCertificate(GetCertificateState),
    AfterCertificate,
    Authenticated,
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Default)]
pub struct GetCertificateState {
    pub current_slot_id: u8,
    pub offset: u16,
    pub remainder_length: Option<u16>,
}
