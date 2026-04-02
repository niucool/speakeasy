// Integration tests

#[cfg(test)]
mod tests {
    use speakeasy::{Speakeasy, SpeakeasyConfig};

    #[test]
    fn test_emulator_creation() {
        let result = Speakeasy::new(None);
        assert!(result.is_ok(), "Failed to create emulator");
    }

    #[test]
    fn test_emulator_with_config() {
        let config = SpeakeasyConfig::default();
        let result = Speakeasy::new(Some(config));
        assert!(result.is_ok(), "Failed to create emulator with config");
    }

    #[test]
    fn test_emulator_report() {
        let emulator = Speakeasy::new(None).unwrap();
        let result = emulator.get_json_report();
        assert!(result.is_ok(), "Failed to get JSON report");
        
        let json = result.unwrap();
        assert!(!json.is_empty(), "Report is empty");
    }
}
