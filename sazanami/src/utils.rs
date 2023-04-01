use bytes::Bytes;
use bytes::BytesMut;
use rand;
use rand::RngCore;

pub fn gen_random_bytes(len: usize) -> Bytes {
    let mut iv = BytesMut::with_capacity(len);
    unsafe {
        iv.set_len(len);
    }

    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut iv);
    iv.freeze()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_gen_random_bytes() {
        let b1 = gen_random_bytes(16);
        let b2 = gen_random_bytes(16);

        assert_ne!(b1, b2);
    }
}
