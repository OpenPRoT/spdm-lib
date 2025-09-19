// Licensed under the Apache-2.0 license

//! Linux Evidence Collection Implementation
//! 
//! This module provides a Linux-specific implementation of evidence collection
//! for SPDM attestation, including device measurements and platform state.

use std::fs;
use std::path::Path;
use serde::{Deserialize, Serialize};
use crate::platform::evidence::SpdmEvidence;
use crate::error::{SpdmResult, SpdmError};

/// Linux-specific evidence collector
pub struct LinuxEvidence {
    measurements: DeviceMeasurements,
}

/// Device measurements structure that can be loaded from JSON
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceMeasurements {
    /// Device firmware measurements
    pub firmware: FirmwareMeasurements,
    /// Hardware measurements
    pub hardware: HardwareMeasurements,
    /// Boot measurements
    pub boot: BootMeasurements,
    /// Runtime measurements
    pub runtime: RuntimeMeasurements,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareMeasurements {
    /// Firmware version
    pub version: String,
    /// Firmware hash (SHA-384)
    pub hash: Vec<u8>,
    /// Firmware build date
    pub build_date: String,
    /// Firmware size in bytes
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareMeasurements {
    /// CPU model
    pub cpu_model: String,
    /// CPU vendor
    pub cpu_vendor: String,
    /// Memory size in bytes
    pub memory_size: u64,
    /// Hardware serial number
    pub serial_number: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootMeasurements {
    /// Boot loader hash
    pub bootloader_hash: Vec<u8>,
    /// Kernel hash
    pub kernel_hash: Vec<u8>,
    /// Init RAM disk hash
    pub initrd_hash: Vec<u8>,
    /// Boot time timestamp
    pub boot_time: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeMeasurements {
    /// Running processes count
    pub process_count: u32,
    /// System uptime in seconds
    pub uptime: u64,
    /// Load average
    pub load_average: f64,
    /// Available memory in bytes
    pub available_memory: u64,
}

impl Default for DeviceMeasurements {
    fn default() -> Self {
        Self {
            firmware: FirmwareMeasurements {
                version: "1.0.0".to_string(),
                hash: vec![0u8; 48], // SHA-384 hash size
                build_date: "2024-01-01T00:00:00Z".to_string(),
                size: 1024 * 1024, // 1MB
            },
            hardware: HardwareMeasurements {
                cpu_model: "Generic CPU".to_string(),
                cpu_vendor: "Generic Vendor".to_string(),
                memory_size: 8 * 1024 * 1024 * 1024, // 8GB
                serial_number: "000000000000".to_string(),
            },
            boot: BootMeasurements {
                bootloader_hash: vec![0u8; 48],
                kernel_hash: vec![0u8; 48],
                initrd_hash: vec![0u8; 48],
                boot_time: 1640995200, // Unix timestamp
            },
            runtime: RuntimeMeasurements {
                process_count: 100,
                uptime: 3600, // 1 hour
                load_average: 0.5,
                available_memory: 4 * 1024 * 1024 * 1024, // 4GB
            },
        }
    }
}

impl LinuxEvidence {
    /// Create a new Linux evidence collector
    pub fn new(measurements_path: Option<&str>) -> SpdmResult<Self> {
        let measurements = if let Some(path) = measurements_path {
            Self::load_measurements_from_file(path)?
        } else {
            Self::collect_system_measurements()?
        };

        Ok(Self { measurements })
    }

    /// Load measurements from a JSON file
    fn load_measurements_from_file(path: &str) -> SpdmResult<DeviceMeasurements> {
        if !Path::new(path).exists() {
            // Create a default measurements file if it doesn't exist
            let default_measurements = DeviceMeasurements::default();
            let json_data = serde_json::to_string_pretty(&default_measurements)
                .map_err(|e| SpdmError::Platform(format!("Failed to serialize default measurements: {}", e)))?;
            
            fs::write(path, json_data)
                .map_err(|e| SpdmError::Platform(format!("Failed to write default measurements to {}: {}", path, e)))?;
            
            println!("Created default measurements file at: {}", path);
            return Ok(default_measurements);
        }

        let json_data = fs::read_to_string(path)
            .map_err(|e| SpdmError::Platform(format!("Failed to read measurements from {}: {}", path, e)))?;

        let measurements: DeviceMeasurements = serde_json::from_str(&json_data)
            .map_err(|e| SpdmError::Platform(format!("Failed to parse measurements JSON: {}", e)))?;

        Ok(measurements)
    }

    /// Collect measurements from the running system
    fn collect_system_measurements() -> SpdmResult<DeviceMeasurements> {
        let mut measurements = DeviceMeasurements::default();

        // Try to collect real system information
        if let Ok(uptime_str) = fs::read_to_string("/proc/uptime") {
            if let Some(uptime_part) = uptime_str.split_whitespace().next() {
                if let Ok(uptime) = uptime_part.parse::<f64>() {
                    measurements.runtime.uptime = uptime as u64;
                }
            }
        }

        if let Ok(meminfo) = fs::read_to_string("/proc/meminfo") {
            for line in meminfo.lines() {
                if line.starts_with("MemTotal:") {
                    if let Some(size_str) = line.split_whitespace().nth(1) {
                        if let Ok(size_kb) = size_str.parse::<u64>() {
                            measurements.hardware.memory_size = size_kb * 1024;
                        }
                    }
                }
                if line.starts_with("MemAvailable:") {
                    if let Some(size_str) = line.split_whitespace().nth(1) {
                        if let Ok(size_kb) = size_str.parse::<u64>() {
                            measurements.runtime.available_memory = size_kb * 1024;
                        }
                    }
                }
            }
        }

        if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
            for line in cpuinfo.lines() {
                if line.starts_with("model name") {
                    if let Some(model) = line.split(':').nth(1) {
                        measurements.hardware.cpu_model = model.trim().to_string();
                        break;
                    }
                }
            }
        }

        // Simulate firmware hash based on system information
        let system_info = format!("{}{}{}", 
            measurements.hardware.cpu_model,
            measurements.hardware.memory_size,
            measurements.runtime.uptime
        );
        
        // Simple hash simulation (in production, use real cryptographic hash)
        let hash_data = system_info.as_bytes();
        measurements.firmware.hash = hash_data.iter()
            .cycle()
            .take(48)
            .cloned()
            .collect();

        Ok(measurements)
    }
}

impl SpdmEvidence for LinuxEvidence {
    fn get_measurements(&self, measurement_index: u8) -> SpdmResult<Vec<u8>> {
        // Convert measurements to a serialized format based on index
        match measurement_index {
            0 => {
                // Firmware measurements
                let mut data = Vec::new();
                data.extend_from_slice(self.measurements.firmware.version.as_bytes());
                data.extend_from_slice(&self.measurements.firmware.hash);
                data.extend_from_slice(&self.measurements.firmware.size.to_le_bytes());
                Ok(data)
            }
            1 => {
                // Hardware measurements
                let mut data = Vec::new();
                data.extend_from_slice(self.measurements.hardware.cpu_model.as_bytes());
                data.extend_from_slice(self.measurements.hardware.cpu_vendor.as_bytes());
                data.extend_from_slice(&self.measurements.hardware.memory_size.to_le_bytes());
                data.extend_from_slice(self.measurements.hardware.serial_number.as_bytes());
                Ok(data)
            }
            2 => {
                // Boot measurements
                let mut data = Vec::new();
                data.extend_from_slice(&self.measurements.boot.bootloader_hash);
                data.extend_from_slice(&self.measurements.boot.kernel_hash);
                data.extend_from_slice(&self.measurements.boot.initrd_hash);
                data.extend_from_slice(&self.measurements.boot.boot_time.to_le_bytes());
                Ok(data)
            }
            3 => {
                // Runtime measurements
                let mut data = Vec::new();
                data.extend_from_slice(&self.measurements.runtime.process_count.to_le_bytes());
                data.extend_from_slice(&self.measurements.runtime.uptime.to_le_bytes());
                data.extend_from_slice(&self.measurements.runtime.load_average.to_le_bytes());
                data.extend_from_slice(&self.measurements.runtime.available_memory.to_le_bytes());
                Ok(data)
            }
            _ => Err(SpdmError::InvalidParam),
        }
    }

    fn get_measurement_count(&self) -> u8 {
        4 // firmware, hardware, boot, runtime
    }

    fn supports_signed_measurements(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn test_default_measurements() {
        let measurements = DeviceMeasurements::default();
        assert_eq!(measurements.firmware.version, "1.0.0");
        assert_eq!(measurements.firmware.hash.len(), 48);
        assert!(measurements.hardware.memory_size > 0);
    }

    #[test]
    fn test_linux_evidence_creation() {
        let result = LinuxEvidence::new(None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_measurements() {
        let evidence = LinuxEvidence::new(None).unwrap();
        
        // Test each measurement index
        for i in 0..4 {
            let result = evidence.get_measurements(i);
            assert!(result.is_ok());
            assert!(!result.unwrap().is_empty());
        }
        
        // Test invalid index
        let result = evidence.get_measurements(5);
        assert!(result.is_err());
    }

    #[test]
    fn test_measurement_count() {
        let evidence = LinuxEvidence::new(None).unwrap();
        assert_eq!(evidence.get_measurement_count(), 4);
    }

    #[test]
    fn test_supports_signed_measurements() {
        let evidence = LinuxEvidence::new(None).unwrap();
        assert!(evidence.supports_signed_measurements());
    }

    #[test]
    fn test_load_from_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let measurements = DeviceMeasurements::default();
        let json_data = serde_json::to_string_pretty(&measurements).unwrap();
        
        write!(temp_file, "{}", json_data).unwrap();
        
        let result = LinuxEvidence::new(Some(temp_file.path().to_str().unwrap()));
        assert!(result.is_ok());
    }
}