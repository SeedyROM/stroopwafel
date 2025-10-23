#![no_main]

use libfuzzer_sys::fuzz_target;
use stroopwafel::predicate::Predicate;
use std::collections::HashMap;

fuzz_target!(|data: &[u8]| {
    // Try to parse predicates from random UTF-8 strings
    if let Ok(s) = std::str::from_utf8(data) {
        // Try to parse as predicate
        if let Ok(predicate) = Predicate::parse(s) {
            // Create various contexts to evaluate against
            let mut context = HashMap::new();

            // Add the key from the predicate with various values
            context.insert(predicate.key.clone(), predicate.value.clone());
            let _ = predicate.evaluate(&context);

            // Try with empty value
            context.insert(predicate.key.clone(), String::new());
            let _ = predicate.evaluate(&context);

            // Try with numeric values
            context.insert(predicate.key.clone(), "0".to_string());
            let _ = predicate.evaluate(&context);

            context.insert(predicate.key.clone(), "123".to_string());
            let _ = predicate.evaluate(&context);

            context.insert(predicate.key.clone(), "-456".to_string());
            let _ = predicate.evaluate(&context);

            context.insert(predicate.key.clone(), "999999999999999".to_string());
            let _ = predicate.evaluate(&context);

            // Try with different string values
            context.insert(predicate.key.clone(), "a".to_string());
            let _ = predicate.evaluate(&context);

            context.insert(predicate.key.clone(), "zzz".to_string());
            let _ = predicate.evaluate(&context);

            // Try with special characters
            context.insert(predicate.key.clone(), "!@#$%".to_string());
            let _ = predicate.evaluate(&context);

            // Try with empty context
            let empty_context = HashMap::new();
            let _ = predicate.evaluate(&empty_context);

            // Try with different key
            let mut wrong_key_context = HashMap::new();
            wrong_key_context.insert("different_key".to_string(), predicate.value.clone());
            let _ = predicate.evaluate(&wrong_key_context);

            // Try with floating point values
            context.insert(predicate.key.clone(), "3.14".to_string());
            let _ = predicate.evaluate(&context);

            context.insert(predicate.key.clone(), "0.0".to_string());
            let _ = predicate.evaluate(&context);

            context.insert(predicate.key.clone(), "-0.5".to_string());
            let _ = predicate.evaluate(&context);

            // Try with timestamps/dates
            context.insert(predicate.key.clone(), "2025-01-01T00:00:00Z".to_string());
            let _ = predicate.evaluate(&context);

            // Try with very long strings
            let long_string = "x".repeat(1000);
            context.insert(predicate.key.clone(), long_string);
            let _ = predicate.evaluate(&context);
        }

        // Also test operator parsing edge cases
        let test_strings = [
            "key=value",
            "key = value",
            "key  =  value",
            "  key  =  value  ",
            "key!=value",
            "key != value",
            "key<value",
            "key < value",
            "key>value",
            "key > value",
            "key<=value",
            "key <= value",
            "key>=value",
            "key >= value",
        ];

        for test in &test_strings {
            let _ = Predicate::parse(test);
        }
    }
});
