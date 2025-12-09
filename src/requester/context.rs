use crate::protocol::capabilities::DeviceCapabilities;
use crate::platform::rng::SpdmRng;
use crate::protocol::algorithms::LocalDeviceAlgorithms;
use crate::protocol::version::SpdmVersion;

pub struct SpdmRequesterContext<'versions, 'algorithms, 'rng> {
    supported_versions: &'versions [SpdmVersion],
    capabilities: DeviceCapabilities,
    algorithms: LocalDeviceAlgorithms<'algorithms>,
    rng: &'rng mut dyn SpdmRng,
}

impl<'versions, 'algorithms, 'rng> SpdmRequesterContext<'versions, 'algorithms, 'rng> {
    pub fn new(
        supported_versions: &'versions [SpdmVersion],
        capabilities: DeviceCapabilities,
        algorithms: LocalDeviceAlgorithms<'algorithms>,
        rng: &'rng mut dyn SpdmRng,
    ) -> Self {
        Self {
            supported_versions,
            capabilities,
            algorithms,
            rng,
        }
    }
}