#![no_main]

use libfuzzer_sys::fuzz_target;
use stroopwafel::Stroopwafel;

fuzz_target!(|data: &[u8]| {
    // Fuzz MessagePack deserialization
    if let Ok(token) = Stroopwafel::from_msgpack(data) {
        // If deserialization succeeds, try serializing back
        let _ = token.to_msgpack();
        let _ = token.to_base64();
        let _ = token.to_hex();
        let _ = token.to_json();

        // Try basic operations
        let _ = token.caveat_count();
        let _ = token.is_unrestricted();
    }

    // Also try base64 deserialization if it's valid UTF-8
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(token) = Stroopwafel::from_base64(s) {
            let _ = token.to_msgpack();
        }

        // Try hex deserialization
        if let Ok(token) = Stroopwafel::from_hex(s) {
            let _ = token.to_msgpack();
        }

        // Try JSON deserialization
        if let Ok(token) = Stroopwafel::from_json(s) {
            let _ = token.to_msgpack();
        }
    }
});
