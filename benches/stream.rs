use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use aead::stream::StreamPrimitive;
use no_noncense::aes_gcm_se3_hmac::Aes128GcmSE3Hmac;
use no_noncense::aes_gcm_se3_xor::Aes128GcmSE3Xor;

const MESSAGE_SIZES: [usize; 1] = [16];
const NUMBER_OF_MESSAGES: [usize; 1] = [1];

macro_rules! benchmark_stream {
    ($group_name:expr, $algorithm:tt, $c:expr) => {
        let mut group = $c.benchmark_group($group_name);

        let key = $algorithm::generate_key();
        let nonce = $algorithm::generate_nonce();

        for num_msgs in NUMBER_OF_MESSAGES {
            for size in MESSAGE_SIZES {
                // pick random plaintexts and associated data of specified size
                let mut plaintext = vec![];
                let mut associated_data = vec![];
                for _ in 0..num_msgs {
                    let mut pt = vec![0u8; size];
                    getrandom::getrandom(&mut pt).unwrap();
                    plaintext.push(pt);
                    let mut ad = vec![0u8; size];
                    getrandom::getrandom(&mut ad).unwrap();
                    associated_data.push(ad);
                }
                let mut plaintext = black_box(plaintext);
                let associated_data = black_box(associated_data);

                group.throughput(Throughput::Bytes((size * num_msgs) as u64));
                let id = num_msgs.to_string() + "-" + &size.to_string();
                group.bench_function(BenchmarkId::new(id, "encrypt"), |b| {
                    b.iter(|| {
                        let x = $algorithm::new(&key, &nonce);
                        let mut encryptor = x.encryptor();
                        for i in 0..(num_msgs - 1) {
                            encryptor
                                .encrypt_next_in_place(&associated_data[i], &mut plaintext[i])
                                .unwrap();
                        }
                        encryptor
                            .encrypt_last_in_place(
                                &associated_data[num_msgs - 1],
                                &mut plaintext[num_msgs - 1],
                            )
                            .unwrap();
                    })
                });
                // TODO: measure decryption cost
            }
        }
        group.finish();
    };
}

fn benchmark_all_streams(c: &mut Criterion) {
    benchmark_stream!("aes_gcm_se3_hmac", Aes128GcmSE3Hmac, c);
    benchmark_stream!("aes_gcm_se3_xor", Aes128GcmSE3Xor, c);
}

criterion_group!(
    name = stream_perf;
    config = Criterion::default();
    targets = benchmark_all_streams
);

criterion_main!(stream_perf);
