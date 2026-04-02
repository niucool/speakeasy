// Unit tests

#[cfg(test)]
mod tests {
    use speakeasy::config::SpeakeasyConfig;
    use speakeasy::error::Result;

    #[test]
    fn test_config_default() {
        let config = SpeakeasyConfig::default();
        assert_eq!(config.memory.stack_size, 2 * 1024 * 1024);
        assert_eq!(config.memory.heap_size, 512 * 1024 * 1024);
    }

    #[test]
    fn test_config_serialization() -> Result<()> {
        let config = SpeakeasyConfig::default();
        let json = config.to_json()?;
        assert!(!json.is_empty());

        let config2 = SpeakeasyConfig::from_json(&json)?;
        assert_eq!(config2.memory.stack_size, config.memory.stack_size);
        Ok(())
    }

    #[test]
    fn test_config_filesystem() -> Result<()> {
        let config = SpeakeasyConfig::default();
        let temp_file = "test_config.json";
        
        config.save_to_file(temp_file)?;
        let loaded = SpeakeasyConfig::from_file(temp_file)?;
        
        assert_eq!(loaded.memory.stack_size, config.memory.stack_size);
        
        std::fs::remove_file(temp_file)?;
        Ok(())
    }
}
