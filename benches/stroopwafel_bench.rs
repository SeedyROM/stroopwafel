use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use std::collections::HashMap;
use stroopwafel::{
    Stroopwafel,
    verifier::{AcceptAllVerifier, ContextVerifier},
};

fn bench_stroopwafel_new(c: &mut Criterion) {
    let root_key = b"super_secret_key_for_benchmarking";

    c.bench_function("stroopwafel_new", |b| {
        b.iter(|| {
            Stroopwafel::new(
                black_box(root_key),
                black_box(b"identifier-12345"),
                Some("https://example.com"),
            )
        })
    });
}

fn bench_add_first_party_caveat(c: &mut Criterion) {
    let root_key = b"super_secret_key_for_benchmarking";

    c.bench_function("add_first_party_caveat", |b| {
        b.iter(|| {
            let mut s = Stroopwafel::new(root_key, b"identifier", Some("https://example.com"));
            s.add_first_party_caveat(black_box(b"account = alice"));
        })
    });
}

fn bench_add_multiple_caveats(c: &mut Criterion) {
    let root_key = b"super_secret_key_for_benchmarking";
    let mut group = c.benchmark_group("add_multiple_caveats");

    for count in [1, 5, 10, 20].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(count), count, |b, &count| {
            b.iter(|| {
                let mut s = Stroopwafel::new(root_key, b"identifier", Some("https://example.com"));
                for i in 0..count {
                    s.add_first_party_caveat(black_box(format!("caveat_{i} = value").as_bytes()));
                }
            })
        });
    }
    group.finish();
}

fn bench_verify_no_caveats(c: &mut Criterion) {
    let root_key = b"super_secret_key_for_benchmarking";
    let s = Stroopwafel::new(root_key, b"identifier", Some("https://example.com"));
    let verifier = AcceptAllVerifier;

    c.bench_function("verify_no_caveats", |b| {
        b.iter(|| {
            s.verify(black_box(root_key), black_box(&verifier), &[])
                .unwrap();
            black_box(())
        })
    });
}

fn bench_verify_with_caveats(c: &mut Criterion) {
    let root_key = b"super_secret_key_for_benchmarking";
    let mut group = c.benchmark_group("verify_with_caveats");

    for count in [1, 5, 10, 20].iter() {
        let mut s = Stroopwafel::new(root_key, b"identifier", Some("https://example.com"));
        let mut context = HashMap::new();

        for i in 0..*count {
            let key = format!("key_{i}");
            let value = format!("value_{i}");
            s.add_first_party_caveat(format!("{key} = {value}").as_bytes());
            context.insert(key, value);
        }

        let verifier = ContextVerifier::new(context);

        group.bench_with_input(BenchmarkId::from_parameter(count), count, |b, _count| {
            b.iter(|| {
                s.verify(black_box(root_key), black_box(&verifier), &[])
                    .unwrap();
                black_box(())
            })
        });
    }
    group.finish();
}

fn bench_serialization_json(c: &mut Criterion) {
    let root_key = b"super_secret_key_for_benchmarking";
    let mut s = Stroopwafel::new(root_key, b"identifier", Some("https://example.com"));
    s.add_first_party_caveat(b"account = alice");
    s.add_first_party_caveat(b"action = read");
    s.add_first_party_caveat(b"resource = /api/data");

    let json = s.to_json().unwrap();

    c.bench_function("serialize_to_json", |b| {
        b.iter(|| black_box(s.to_json().unwrap()))
    });

    c.bench_function("deserialize_from_json", |b| {
        b.iter(|| black_box(Stroopwafel::from_json(black_box(&json)).unwrap()))
    });
}

fn bench_serialization_msgpack(c: &mut Criterion) {
    let root_key = b"super_secret_key_for_benchmarking";
    let mut s = Stroopwafel::new(root_key, b"identifier", Some("https://example.com"));
    s.add_first_party_caveat(b"account = alice");
    s.add_first_party_caveat(b"action = read");
    s.add_first_party_caveat(b"resource = /api/data");

    let msgpack = s.to_msgpack().unwrap();

    c.bench_function("serialize_to_msgpack", |b| {
        b.iter(|| black_box(s.to_msgpack().unwrap()))
    });

    c.bench_function("deserialize_from_msgpack", |b| {
        b.iter(|| black_box(Stroopwafel::from_msgpack(black_box(&msgpack)).unwrap()))
    });
}

fn bench_serialization_base64(c: &mut Criterion) {
    let root_key = b"super_secret_key_for_benchmarking";
    let mut s = Stroopwafel::new(root_key, b"identifier", Some("https://example.com"));
    s.add_first_party_caveat(b"account = alice");
    s.add_first_party_caveat(b"action = read");
    s.add_first_party_caveat(b"resource = /api/data");

    let base64 = s.to_base64().unwrap();

    c.bench_function("serialize_to_base64", |b| {
        b.iter(|| black_box(s.to_base64().unwrap()))
    });

    c.bench_function("deserialize_from_base64", |b| {
        b.iter(|| black_box(Stroopwafel::from_base64(black_box(&base64)).unwrap()))
    });
}

fn bench_third_party_caveats(c: &mut Criterion) {
    let root_key = b"super_secret_key_for_benchmarking";
    let third_party_key = b"third_party_secret_key";

    c.bench_function("add_third_party_caveat", |b| {
        b.iter(|| {
            let mut s = Stroopwafel::new(root_key, b"identifier", Some("https://example.com"));
            s.add_third_party_caveat(
                black_box(b"user_authenticated"),
                black_box(third_party_key),
                black_box("https://auth.example.com"),
            );
        })
    });

    c.bench_function("create_discharge", |b| {
        b.iter(|| {
            Stroopwafel::create_discharge(
                black_box(third_party_key),
                black_box(b"user_authenticated"),
                Some("https://auth.example.com"),
            )
        })
    });

    // Benchmark binding discharge
    let mut primary = Stroopwafel::new(root_key, b"identifier", Some("https://example.com"));
    primary.add_third_party_caveat(
        b"user_authenticated",
        third_party_key,
        "https://auth.example.com",
    );

    let discharge = Stroopwafel::create_discharge(
        third_party_key,
        b"user_authenticated",
        Some("https://auth.example.com"),
    );

    c.bench_function("bind_discharge", |b| {
        b.iter(|| black_box(primary.bind_discharge(black_box(&discharge))))
    });

    // Benchmark verification with discharge
    let bound_discharge = primary.bind_discharge(&discharge);
    let verifier = AcceptAllVerifier;

    c.bench_function("verify_with_discharge", |b| {
        b.iter(|| {
            primary
                .verify(
                    black_box(root_key),
                    black_box(&verifier),
                    black_box(&[bound_discharge.clone()]),
                )
                .unwrap();
            black_box(())
        })
    });
}

fn bench_predicate_parsing(c: &mut Criterion) {
    use stroopwafel::predicate::Predicate;

    let predicates = [
        "account = alice",
        "count < 100",
        "level >= 5",
        "time < 2025-12-31T23:59:59Z",
        "status != banned",
    ];

    c.bench_function("predicate_parse", |b| {
        b.iter(|| {
            for pred_str in &predicates {
                black_box(Predicate::parse(black_box(pred_str)).unwrap());
            }
        })
    });
}

fn bench_predicate_evaluation(c: &mut Criterion) {
    use stroopwafel::predicate::Predicate;

    let mut context = HashMap::new();
    context.insert("account".to_string(), "alice".to_string());
    context.insert("count".to_string(), "50".to_string());
    context.insert("level".to_string(), "10".to_string());
    context.insert("time".to_string(), "2025-01-01T00:00:00Z".to_string());
    context.insert("status".to_string(), "active".to_string());

    let predicates = [
        Predicate::parse("account = alice").unwrap(),
        Predicate::parse("count < 100").unwrap(),
        Predicate::parse("level >= 5").unwrap(),
        Predicate::parse("time < 2025-12-31T23:59:59Z").unwrap(),
        Predicate::parse("status != banned").unwrap(),
    ];

    c.bench_function("predicate_evaluate", |b| {
        b.iter(|| {
            for pred in &predicates {
                black_box(pred.evaluate(black_box(&context)));
            }
        })
    });
}

fn bench_context_verifier(c: &mut Criterion) {
    let root_key = b"super_secret_key_for_benchmarking";
    let mut s = Stroopwafel::new(root_key, b"identifier", Some("https://example.com"));

    s.add_first_party_caveat(b"account = alice");
    s.add_first_party_caveat(b"action = read");
    s.add_first_party_caveat(b"resource = /api/data");
    s.add_first_party_caveat(b"count < 100");
    s.add_first_party_caveat(b"level >= 5");

    let verifier = ContextVerifier::empty()
        .with("account", "alice")
        .with("action", "read")
        .with("resource", "/api/data")
        .with("count", "50")
        .with("level", "10");

    c.bench_function("context_verifier_verify", |b| {
        b.iter(|| {
            s.verify(black_box(root_key), black_box(&verifier), &[])
                .unwrap();
            black_box(())
        })
    });
}

criterion_group!(
    benches,
    bench_stroopwafel_new,
    bench_add_first_party_caveat,
    bench_add_multiple_caveats,
    bench_verify_no_caveats,
    bench_verify_with_caveats,
    bench_serialization_json,
    bench_serialization_msgpack,
    bench_serialization_base64,
    bench_third_party_caveats,
    bench_predicate_parsing,
    bench_predicate_evaluation,
    bench_context_verifier,
);

criterion_main!(benches);
