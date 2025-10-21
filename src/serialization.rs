use crate::{Result, Stroopwafel, StroopwafelError};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

impl Stroopwafel {
    /// Serializes this stroopwafel to JSON
    ///
    /// Binary data (identifier, signature, caveat IDs) are base64-encoded in the JSON output.
    ///
    /// # Example
    /// ```
    /// use stroopwafel::Stroopwafel;
    ///
    /// let root_key = b"secret";
    /// let mut stroopwafel = Stroopwafel::new(root_key, b"my-identifier", Some("http://example.com/"));
    /// stroopwafel.add_first_party_caveat(b"account = alice");
    ///
    /// let json = stroopwafel.to_json().unwrap();
    /// println!("{}", json);
    /// ```
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self)
            .map_err(|e| StroopwafelError::DeserializationError(e.to_string()))
    }

    /// Serializes this stroopwafel to pretty-printed JSON
    ///
    /// # Example
    /// ```
    /// use stroopwafel::Stroopwafel;
    ///
    /// let root_key = b"secret";
    /// let stroopwafel = Stroopwafel::new(root_key, b"my-identifier", None::<String>);
    /// let json = stroopwafel.to_json_pretty().unwrap();
    /// assert!(json.contains("identifier"));
    /// ```
    pub fn to_json_pretty(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| StroopwafelError::DeserializationError(e.to_string()))
    }

    /// Deserializes a stroopwafel from JSON
    ///
    /// # Example
    /// ```
    /// use stroopwafel::Stroopwafel;
    ///
    /// let root_key = b"secret";
    /// let original = Stroopwafel::new(root_key, b"my-identifier", Some("http://example.com/"));
    /// let json = original.to_json().unwrap();
    ///
    /// let deserialized = Stroopwafel::from_json(&json).unwrap();
    /// assert_eq!(original, deserialized);
    /// ```
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json)
            .map_err(|e| StroopwafelError::DeserializationError(e.to_string()))
    }

    /// Serializes this stroopwafel to MessagePack binary format
    ///
    /// MessagePack is a compact, standardized binary format that's interoperable
    /// with many programming languages.
    ///
    /// # Example
    /// ```
    /// use stroopwafel::Stroopwafel;
    ///
    /// let root_key = b"secret";
    /// let stroopwafel = Stroopwafel::new(root_key, b"my-identifier", None::<String>);
    /// let msgpack = stroopwafel.to_msgpack().unwrap();
    /// assert!(!msgpack.is_empty());
    /// ```
    pub fn to_msgpack(&self) -> Result<Vec<u8>> {
        rmp_serde::to_vec(self).map_err(|e| StroopwafelError::DeserializationError(e.to_string()))
    }

    /// Deserializes a stroopwafel from MessagePack binary format
    ///
    /// # Example
    /// ```
    /// use stroopwafel::Stroopwafel;
    ///
    /// let root_key = b"secret";
    /// let mut original = Stroopwafel::new(root_key, b"my-identifier", Some("http://example.com/"));
    /// original.add_first_party_caveat(b"account = alice");
    ///
    /// let msgpack = original.to_msgpack().unwrap();
    /// let deserialized = Stroopwafel::from_msgpack(&msgpack).unwrap();
    /// assert_eq!(original, deserialized);
    /// ```
    pub fn from_msgpack(data: &[u8]) -> Result<Self> {
        rmp_serde::from_slice(data)
            .map_err(|e| StroopwafelError::DeserializationError(e.to_string()))
    }

    /// Serializes this stroopwafel to a base64-encoded string (MessagePack encoding)
    ///
    /// This uses URL-safe base64 encoding without padding, suitable for HTTP headers.
    /// The underlying data is MessagePack format.
    ///
    /// # Example
    /// ```
    /// use stroopwafel::Stroopwafel;
    ///
    /// let root_key = b"secret";
    /// let stroopwafel = Stroopwafel::new(root_key, b"my-identifier", None::<String>);
    /// let b64 = stroopwafel.to_base64().unwrap();
    /// println!("Base64: {}", b64);
    /// ```
    pub fn to_base64(&self) -> Result<String> {
        let msgpack = self.to_msgpack()?;
        Ok(URL_SAFE_NO_PAD.encode(&msgpack))
    }

    /// Deserializes a stroopwafel from a base64-encoded string (MessagePack encoding)
    ///
    /// # Example
    /// ```
    /// use stroopwafel::Stroopwafel;
    ///
    /// let root_key = b"secret";
    /// let original = Stroopwafel::new(root_key, b"my-identifier", Some("http://example.com/"));
    /// let b64 = original.to_base64().unwrap();
    ///
    /// let deserialized = Stroopwafel::from_base64(&b64).unwrap();
    /// assert_eq!(original, deserialized);
    /// ```
    pub fn from_base64(b64: &str) -> Result<Self> {
        let bytes = URL_SAFE_NO_PAD
            .decode(b64.as_bytes())
            .map_err(|e| StroopwafelError::DeserializationError(e.to_string()))?;

        Self::from_msgpack(&bytes)
    }

    /// Serializes this stroopwafel to a hex string (MessagePack encoding)
    ///
    /// # Example
    /// ```
    /// use stroopwafel::Stroopwafel;
    ///
    /// let root_key = b"secret";
    /// let stroopwafel = Stroopwafel::new(root_key, b"my-identifier", None::<String>);
    /// let hex_str = stroopwafel.to_hex().unwrap();
    /// assert!(hex_str.len() > 0);
    /// ```
    pub fn to_hex(&self) -> Result<String> {
        let msgpack = self.to_msgpack()?;
        Ok(hex::encode(&msgpack))
    }

    /// Deserializes a stroopwafel from a hex string (MessagePack encoding)
    ///
    /// # Example
    /// ```
    /// use stroopwafel::Stroopwafel;
    ///
    /// let root_key = b"secret";
    /// let original = Stroopwafel::new(root_key, b"my-identifier", None::<String>);
    /// let hex_str = original.to_hex().unwrap();
    ///
    /// let deserialized = Stroopwafel::from_hex(&hex_str).unwrap();
    /// assert_eq!(original, deserialized);
    /// ```
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let msgpack = hex::decode(hex_str)
            .map_err(|e| StroopwafelError::DeserializationError(e.to_string()))?;
        Self::from_msgpack(&msgpack)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_roundtrip_no_caveats() {
        let root_key = b"secret";
        let original = Stroopwafel::new(root_key, b"my-identifier", Some("http://example.com/"));

        let json = original.to_json().unwrap();
        let deserialized = Stroopwafel::from_json(&json).unwrap();

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_json_roundtrip_with_caveats() {
        let root_key = b"secret";
        let mut original =
            Stroopwafel::new(root_key, b"my-identifier", Some("http://example.com/"));
        original.add_first_party_caveat(b"account = alice");
        original.add_first_party_caveat(b"action = read");

        let json = original.to_json().unwrap();
        let deserialized = Stroopwafel::from_json(&json).unwrap();

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_json_pretty() {
        let root_key = b"secret";
        let stroopwafel = Stroopwafel::new(root_key, b"my-identifier", None::<String>);

        let json = stroopwafel.to_json_pretty().unwrap();
        assert!(json.contains('\n')); // Pretty-printed should have newlines
        assert!(json.contains("identifier"));
    }

    #[test]
    fn test_msgpack_roundtrip_no_caveats() {
        let root_key = b"secret";
        let original = Stroopwafel::new(root_key, b"my-identifier", Some("http://example.com/"));

        let msgpack = original.to_msgpack().unwrap();
        let deserialized = Stroopwafel::from_msgpack(&msgpack).unwrap();

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_msgpack_roundtrip_with_first_party_caveats() {
        let root_key = b"secret";
        let mut original =
            Stroopwafel::new(root_key, b"my-identifier", Some("http://example.com/"));
        original.add_first_party_caveat(b"account = alice");
        original.add_first_party_caveat(b"action = read");

        let msgpack = original.to_msgpack().unwrap();
        let deserialized = Stroopwafel::from_msgpack(&msgpack).unwrap();

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_msgpack_roundtrip_with_third_party_caveats() {
        let root_key = b"secret";
        let mut original =
            Stroopwafel::new(root_key, b"my-identifier", Some("http://example.com/"));
        original.add_first_party_caveat(b"account = alice");
        original.add_third_party_caveat(
            b"external_check",
            b"encrypted_key_123",
            "https://auth.example.com",
        );

        let msgpack = original.to_msgpack().unwrap();
        let deserialized = Stroopwafel::from_msgpack(&msgpack).unwrap();

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_msgpack_is_compact() {
        let root_key = b"secret";
        let mut stroopwafel =
            Stroopwafel::new(root_key, b"my-identifier", Some("http://example.com/"));
        stroopwafel.add_first_party_caveat(b"account = alice");

        let msgpack = stroopwafel.to_msgpack().unwrap();
        let json = stroopwafel.to_json().unwrap();

        // MessagePack should be more compact than JSON
        assert!(msgpack.len() < json.len());
    }

    #[test]
    fn test_base64_roundtrip() {
        let root_key = b"secret";
        let mut original =
            Stroopwafel::new(root_key, b"my-identifier", Some("http://example.com/"));
        original.add_first_party_caveat(b"account = alice");

        let b64 = original.to_base64().unwrap();
        let deserialized = Stroopwafel::from_base64(&b64).unwrap();

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_hex_roundtrip() {
        let root_key = b"secret";
        let mut original = Stroopwafel::new(root_key, b"my-identifier", None::<String>);
        original.add_first_party_caveat(b"account = alice");

        let hex_str = original.to_hex().unwrap();
        let deserialized = Stroopwafel::from_hex(&hex_str).unwrap();

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_invalid_json() {
        let result = Stroopwafel::from_json("not valid json");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_base64() {
        let result = Stroopwafel::from_base64("!!!invalid base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_hex() {
        let result = Stroopwafel::from_hex("zzz");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_msgpack() {
        let result = Stroopwafel::from_msgpack(&[0xff, 0xff, 0xff]); // Invalid MessagePack
        assert!(result.is_err());
    }

    #[test]
    fn test_cross_format_incompatibility() {
        let root_key = b"secret";
        let stroopwafel = Stroopwafel::new(root_key, b"my-identifier", None::<String>);

        let json = stroopwafel.to_json().unwrap();

        // JSON can't be parsed as MessagePack directly
        let result = Stroopwafel::from_msgpack(json.as_bytes());
        assert!(result.is_err());
    }
}
