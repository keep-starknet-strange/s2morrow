pub mod falcon;
pub mod ntt;
pub mod ntt_constants;
pub mod ring;

#[derive(Drop, Serde)]
struct Args {
    attestations: Array<Attestation>,
}

#[derive(Drop, Serde)]
struct Attestation {
    s1: Span<u16>,
    pk: Span<u16>,
    msg_point: Span<u16>,
}

#[executable]
fn main(args: Args) {
    let Args { attestations } = args;
    println!("Verifying {} signatures", attestations.len());

    for attestation in attestations {
        falcon::verify_uncompressed::<512>(attestation.s1, attestation.pk, attestation.msg_point)
            .expect('Invalid signature');
    }
    println!("OK");
}
