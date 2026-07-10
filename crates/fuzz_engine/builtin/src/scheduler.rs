// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SeedId(u64);

impl SeedId {
    pub fn from_raw(value: u64) -> Self {
        Self(value)
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScheduleFeedback {
    pub new_exception_signatures: u32,
    pub new_breadcrumb_bits: u32,
}

impl ScheduleFeedback {
    pub fn is_empty(self) -> bool {
        self.new_exception_signatures == 0 && self.new_breadcrumb_bits == 0
    }

    fn accumulate(&mut self, feedback: Self) {
        self.new_exception_signatures = self
            .new_exception_signatures
            .saturating_add(feedback.new_exception_signatures);
        self.new_breadcrumb_bits = self
            .new_breadcrumb_bits
            .saturating_add(feedback.new_breadcrumb_bits);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowerScheduleConfig {
    pub base_energy: u32,
    pub max_energy: u32,
    pub exception_signature_bonus: u32,
    pub breadcrumb_bit_bonus: u32,
}

impl Default for PowerScheduleConfig {
    fn default() -> Self {
        Self {
            base_energy: 1,
            max_energy: 64,
            exception_signature_bonus: 16,
            breadcrumb_bit_bonus: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledSeed {
    pub id: SeedId,
    pub bytes: Vec<u8>,
    pub energy: u32,
    pub priority_score: u64,
}

#[derive(Debug, Clone)]
pub struct PowerScheduler {
    config: PowerScheduleConfig,
    next_id: u64,
    seeds: Vec<SeedEntry>,
}

impl Default for PowerScheduler {
    fn default() -> Self {
        Self::new(PowerScheduleConfig::default())
    }
}

impl PowerScheduler {
    pub fn new(config: PowerScheduleConfig) -> Self {
        Self {
            config,
            next_id: 0,
            seeds: Vec::new(),
        }
    }

    pub fn insert<T: AsRef<[u8]>>(&mut self, bytes: T) -> SeedId {
        self.insert_with_feedback(bytes, ScheduleFeedback::default())
    }

    pub fn insert_with_feedback<T: AsRef<[u8]>>(
        &mut self,
        bytes: T,
        feedback: ScheduleFeedback,
    ) -> SeedId {
        let id = SeedId(self.next_id);
        self.next_id = self.next_id.saturating_add(1);
        self.seeds.push(SeedEntry {
            id,
            bytes: bytes.as_ref().to_vec(),
            feedback,
            selections: 0,
        });
        id
    }

    pub fn len(&self) -> usize {
        self.seeds.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seeds.is_empty()
    }

    pub fn seed_energy(&self, id: SeedId) -> Option<u32> {
        self.seed(id).map(|seed| seed.energy(self.config))
    }

    pub fn record_feedback(&mut self, id: SeedId, feedback: ScheduleFeedback) -> bool {
        let Some(seed) = self.seed_mut(id) else {
            return false;
        };

        seed.feedback.accumulate(feedback);
        true
    }

    pub fn select_next(&mut self) -> Option<ScheduledSeed> {
        let selected_index = self.best_seed_index()?;
        let seed = &mut self.seeds[selected_index];
        let energy = seed.energy(self.config);
        let priority_score = seed.priority_score(self.config);
        seed.selections = seed.selections.saturating_add(1);

        Some(ScheduledSeed {
            id: seed.id,
            bytes: seed.bytes.clone(),
            energy,
            priority_score,
        })
    }

    fn seed(&self, id: SeedId) -> Option<&SeedEntry> {
        self.seeds.iter().find(|seed| seed.id == id)
    }

    fn seed_mut(&mut self, id: SeedId) -> Option<&mut SeedEntry> {
        self.seeds.iter_mut().find(|seed| seed.id == id)
    }

    fn best_seed_index(&self) -> Option<usize> {
        let mut best_index = None;
        let mut best_score = 0_u64;
        let mut best_id = SeedId(u64::MAX);

        for (index, seed) in self.seeds.iter().enumerate() {
            let score = seed.priority_score(self.config);
            if best_index.is_none()
                || score > best_score
                || (score == best_score && seed.id < best_id)
            {
                best_index = Some(index);
                best_score = score;
                best_id = seed.id;
            }
        }

        best_index
    }
}

#[derive(Debug, Clone)]
struct SeedEntry {
    id: SeedId,
    bytes: Vec<u8>,
    feedback: ScheduleFeedback,
    selections: u64,
}

impl SeedEntry {
    fn energy(&self, config: PowerScheduleConfig) -> u32 {
        let raw = config
            .base_energy
            .saturating_add(
                config
                    .exception_signature_bonus
                    .saturating_mul(self.feedback.new_exception_signatures),
            )
            .saturating_add(
                config
                    .breadcrumb_bit_bonus
                    .saturating_mul(self.feedback.new_breadcrumb_bits),
            );
        raw.max(1).min(config.max_energy.max(1))
    }

    fn priority_score(&self, config: PowerScheduleConfig) -> u64 {
        u64::from(self.energy(config)).saturating_mul(1024) / self.selections.saturating_add(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> PowerScheduleConfig {
        PowerScheduleConfig {
            base_energy: 4,
            max_energy: 64,
            exception_signature_bonus: 16,
            breadcrumb_bit_bonus: 2,
        }
    }

    #[test]
    fn empty_scheduler_returns_none() {
        let mut scheduler = PowerScheduler::new(config());

        assert_eq!(scheduler.select_next(), None);
    }

    #[test]
    fn inserting_seed_assigns_stable_ids_and_base_energy() {
        let mut scheduler = PowerScheduler::new(config());
        let first = scheduler.insert(b"alpha");
        let second = scheduler.insert(b"beta");

        assert_eq!(first.as_u64(), 0);
        assert_eq!(second.as_u64(), 1);
        assert_eq!(scheduler.seed_energy(first), Some(4));
        assert_eq!(scheduler.seed_energy(second), Some(4));
    }

    #[test]
    fn feedback_raises_energy_for_novel_seed() {
        let mut scheduler = PowerScheduler::new(config());
        let seed = scheduler.insert(b"input");

        assert!(scheduler.record_feedback(
            seed,
            ScheduleFeedback {
                new_exception_signatures: 1,
                new_breadcrumb_bits: 3,
            },
        ));

        assert_eq!(scheduler.seed_energy(seed), Some(26));
    }

    #[test]
    fn energy_is_clamped_to_configured_max() {
        let mut scheduler = PowerScheduler::new(config());
        let seed = scheduler.insert(b"input");

        assert!(scheduler.record_feedback(
            seed,
            ScheduleFeedback {
                new_exception_signatures: 99,
                new_breadcrumb_bits: 99,
            },
        ));

        assert_eq!(scheduler.seed_energy(seed), Some(64));
    }

    #[test]
    fn select_next_prefers_novel_seed_over_baseline_seed() {
        let mut scheduler = PowerScheduler::new(config());
        let baseline = scheduler.insert(b"baseline");
        let novel = scheduler.insert(b"novel");
        scheduler.record_feedback(
            novel,
            ScheduleFeedback {
                new_exception_signatures: 1,
                new_breadcrumb_bits: 0,
            },
        );

        let selected = scheduler.select_next().expect("seed should be selected");

        assert_eq!(selected.id, novel);
        assert_eq!(selected.bytes, b"novel");
        assert!(selected.energy > scheduler.seed_energy(baseline).unwrap());
    }

    #[test]
    fn select_next_decays_priority_to_round_robin_equal_energy_seeds() {
        let mut scheduler = PowerScheduler::new(config());
        let first = scheduler.insert(b"first");
        let second = scheduler.insert(b"second");

        assert_eq!(scheduler.select_next().unwrap().id, first);
        assert_eq!(scheduler.select_next().unwrap().id, second);
    }

    #[test]
    fn unknown_seed_feedback_returns_false() {
        let mut scheduler = PowerScheduler::new(config());

        assert!(!scheduler.record_feedback(
            SeedId::from_raw(7),
            ScheduleFeedback {
                new_exception_signatures: 1,
                new_breadcrumb_bits: 1,
            },
        ));
    }
}
