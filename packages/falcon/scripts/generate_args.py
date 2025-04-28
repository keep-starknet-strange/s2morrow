from falcon import SecretKey, decompress, HEAD_LEN, SALT_LEN
import json
import argparse

Q=12289

def generate_attestations(n: int, num_signatures: int) -> list[dict]:
    sk = SecretKey(n)
    attestations = [generate_attestation(sk, f'message #{i}'.encode()) for i in range(num_signatures)]
    return attestations


def generate_attestation(sk: SecretKey, message: bytes):
    signature = sk.sign(message)
    salt = signature[HEAD_LEN:HEAD_LEN + SALT_LEN]
    enc_s = signature[HEAD_LEN + SALT_LEN:]
    s1 = decompress(enc_s, sk.sig_bytelen - HEAD_LEN - SALT_LEN, sk.n)
    msg_point = sk.hash_to_point(message, salt)
    return {
        's1': [x % Q for x in s1],
        'pk': sk.h,
        'msg_point': msg_point
    }


def format_args(args: list[dict], n: int):
    serialized = [len(args)]
    for arg in args:
        serialized.extend([
            len(arg['s1']),
            *arg['s1'],
            len(arg['pk']),
            *arg['pk'],
            len(arg['msg_point']),
            *arg['msg_point']
        ])
    serialized.append(n)
    return json.dumps(list(map(hex, serialized)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--n', type=int, default=512)
    parser.add_argument('--num_signatures', type=int, default=1)
    args = parser.parse_args()

    attestations = generate_attestations(args.n, args.num_signatures)
    print(format_args(attestations, args.n))
