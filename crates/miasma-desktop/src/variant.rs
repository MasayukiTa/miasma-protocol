/// Product mode — controls UI density and terminology.
///
/// Both modes share the same backend, protocol, storage, and daemon.
/// The only differences are presentation, defaults, and information density.

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProductMode {
    /// Full diagnostics, transport details, protocol terminology.
    Technical,
    /// Simplified language, hidden internals, product-like UX.
    Easy,
}

impl Default for ProductMode {
    fn default() -> Self {
        Self::Easy
    }
}

impl ProductMode {
    /// Detect product mode from environment, then default.
    pub fn detect() -> Self {
        // 1. CLI arg (checked by caller)
        // 2. Environment variable
        if let Ok(val) = std::env::var("MIASMA_MODE") {
            match val.to_lowercase().as_str() {
                "technical" | "tech" => return Self::Technical,
                "easy" | "simple" => return Self::Easy,
                _ => {}
            }
        }
        // 3. Default
        Self::Easy
    }

    pub fn is_easy(self) -> bool {
        self == Self::Easy
    }

    pub fn is_technical(self) -> bool {
        self == Self::Technical
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_easy() {
        assert_eq!(ProductMode::default(), ProductMode::Easy);
    }

    #[test]
    fn is_easy_and_is_technical_are_exclusive() {
        assert!(ProductMode::Easy.is_easy());
        assert!(!ProductMode::Easy.is_technical());
        assert!(ProductMode::Technical.is_technical());
        assert!(!ProductMode::Technical.is_easy());
    }

    #[test]
    fn serde_roundtrip() {
        let easy_json = serde_json::to_string(&ProductMode::Easy).unwrap();
        assert_eq!(easy_json, "\"easy\"");
        let tech_json = serde_json::to_string(&ProductMode::Technical).unwrap();
        assert_eq!(tech_json, "\"technical\"");
        let easy: ProductMode = serde_json::from_str(&easy_json).unwrap();
        assert_eq!(easy, ProductMode::Easy);
        let tech: ProductMode = serde_json::from_str(&tech_json).unwrap();
        assert_eq!(tech, ProductMode::Technical);
    }
}
