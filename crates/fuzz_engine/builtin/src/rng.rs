// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, Clone)]
pub struct MutationRng {
    state: u64,
}

impl MutationRng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    pub fn next_u8(&mut self) -> u8 {
        self.next_u64() as u8
    }

    pub fn choose_index(&mut self, len: usize) -> Option<usize> {
        if len == 0 {
            None
        } else {
            Some((self.next_u64() as usize) % len)
        }
    }

    pub fn coin(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_produces_same_sequence() {
        let mut left = MutationRng::new(0x4756_4655_5a5a);
        let mut right = MutationRng::new(0x4756_4655_5a5a);

        let left_values: Vec<u64> = (0..8).map(|_| left.next_u64()).collect();
        let right_values: Vec<u64> = (0..8).map(|_| right.next_u64()).collect();

        assert_eq!(left_values, right_values);
    }

    #[test]
    fn choose_index_returns_none_for_zero_len() {
        let mut rng = MutationRng::new(17);

        assert_eq!(rng.choose_index(0), None);
    }

    #[test]
    fn choose_index_stays_below_len() {
        let mut rng = MutationRng::new(23);

        for _ in 0..128 {
            let index = rng.choose_index(7).expect("non-empty length");
            assert!(index < 7);
        }
    }
}
