mod bit_magic {

    pub fn rotr(number: &u32, rotate_by: &u32) -> u32 {
        (number >> rotate_by) | (number << (32 - rotate_by))
    }

    pub fn sig0(number: &u32) -> u32 {
        rotr(&number, &7) ^ rotr(&number, &18) ^ (number >> 3)
    }

    pub fn sig1(number: &u32) -> u32 {
        rotr(&number, &17) ^ rotr(&number, &19) ^ (number >> 10)
    }

    pub fn Sig0(number: &u32) -> u32 {
        rotr(&number, &2) ^ rotr(&number, &13) ^ rotr(&number, &22)
    }

    pub fn Sig1(number: &u32) -> u32 {
        rotr(&number, &6) ^ rotr(&number, &11) ^ rotr(&number, &25)
    }

    pub fn choice(x: &u32, y: &u32, z: &u32) -> u32 {
        (x & y) ^ (!x & z)
    }

    pub fn majority(x: &u32, y: &u32, z: &u32) -> u32 {
        (x & (y | z)) | (y & z)
    }
}

const h: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const k: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

struct Sha256 {
    current_hash: [u32; 8],
    completed_data_blocks: u64,
    pending: [u8; 64],
    num_pending: usize,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self {
            current_hash: h,
            completed_data_blocks: 0,
            pending: [0u8; 64],
            num_pending: 0,
        }
    }
}

impl Sha256 {
    fn update_state(current_hash: &mut [u32; 8], data: &[u8; 64]) {
        let mut w = [0; 64];
        for (w, d) in w.iter_mut().zip(data.iter().step_by(4)).take(16) {
            *w = u32::from_be_bytes(unsafe { *(d as *const u8 as *const [u8; 4]) });
        }

        for i in 16..64 {
            w[i] = w[i - 16]
                .wrapping_add(bit_magic::sig0(&w[i - 15]))
                .wrapping_add(w[i - 7])
                .wrapping_add(bit_magic::sig1(&w[i - 2]));
        }

        let mut w_var = *current_hash;

        for i in 0..64 {
            let t0 = w_var[7]
                .wrapping_add(bit_magic::Sig1(&w_var[4]))
                .wrapping_add(bit_magic::choice(&w_var[4], &w_var[5], &w_var[6]))
                .wrapping_add(k[i])
                .wrapping_add(w[i]);

            let t1 = bit_magic::Sig0(&w_var[0])
                .wrapping_add(bit_magic::majority(&w_var[0], &w_var[1], &w_var[2]));

            w_var[7] = w_var[6];
            w_var[6] = w_var[5];
            w_var[5] = w_var[4];
            w_var[4] = w_var[3].wrapping_add(t0);
            w_var[3] = w_var[2];
            w_var[2] = w_var[1];
            w_var[1] = w_var[0];
            w_var[0] = t0.wrapping_add(t1);
        }

        for (i, v) in current_hash.iter_mut().enumerate() {
            *v = v.wrapping_add(w_var[i]);
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut len = data.len();
        let mut offset = 0;

        if self.num_pending > 0 && self.num_pending + len >= 64 {
            self.pending[self.num_pending..].copy_from_slice(&data[..64 - self.num_pending]);
            Self::update_state(&mut self.current_hash, &self.pending);
            self.completed_data_blocks += 1;
            offset = 64 - self.num_pending;
            len -= offset;
            self.num_pending = 0;
        }

        let data_blocks = len / 64;
        let remain = len % 64;
        for _ in 0..data_blocks {
            Self::update_state(&mut self.current_hash, unsafe {
                &*(data.as_ptr().add(offset) as *const [u8; 64])
            });
            offset += 64;
        }
        self.completed_data_blocks += data_blocks as u64;

        if remain > 0 {
            self.pending[self.num_pending..self.num_pending + remain]
                .copy_from_slice(&data[offset..]);
            self.num_pending += remain;
        }
    }

    pub fn finish(mut self) -> [u8; 32] {
        let data_bits = self.completed_data_blocks * 512 + self.num_pending as u64 * 8;
        let mut pending = [0u8; 72];
        pending[0] = 128;

        let offset = if self.num_pending < 56 {
            56 - self.num_pending
        } else {
            120 - self.num_pending
        };

        pending[offset..offset + 8].copy_from_slice(&data_bits.to_be_bytes());
        self.update(&pending[..offset + 8]);

        for w_var in self.current_hash.iter_mut() {
            *w_var = w_var.to_be();
        }
        unsafe { *(self.current_hash.as_ptr() as *const [u8; 32]) }
    }
}

pub fn digest(data: &[u8]) -> [u8; 32] {
    let mut sha256 = Sha256::default();
    sha256.update(data);
    sha256.finish()
}
