pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }

    pub fn gen_range(&mut self, upper: usize) -> usize {
        if upper == 0 {
            return 0;
        }
        (self.next_u64() as usize) % upper
    }
}

pub fn wilson_score_interval(successes: usize, total: usize, confidence_z: f64) -> (f64, f64) {
    if total == 0 {
        return (0.0, 0.0);
    }
    let n = total as f64;
    let p_hat = successes as f64 / n;
    let z2 = confidence_z * confidence_z;

    let center = (p_hat + z2 / (2.0 * n)) / (1.0 + z2 / n);
    let term = (p_hat * (1.0 - p_hat) / n + z2 / (4.0 * n * n)).max(0.0).sqrt();
    let margin = (confidence_z / (1.0 + z2 / n)) * term;

    let lower = (center - margin).clamp(0.0, 1.0);
    let upper = (center + margin).clamp(0.0, 1.0);
    (lower, upper)
}

fn binom_pmf(n: usize, k: usize) -> f64 {
    if k > n {
        return 0.0;
    }
    let mut log_coeff = 0.0;
    for i in 0..k {
        log_coeff += ((n - i) as f64).ln() - ((i + 1) as f64).ln();
    }
    let log_prob = log_coeff - (n as f64) * 2.0_f64.ln();
    log_prob.exp()
}

pub fn exact_mcnemar_p_value(b: usize, c: usize) -> f64 {
    let n = b + c;
    if n == 0 {
        return 1.0;
    }

    if n < 30 {
        let min_val = b.min(c);
        let mut p_val = 0.0;
        for i in 0..=min_val {
            p_val += binom_pmf(n, i);
        }
        p_val *= 2.0;
        p_val.min(1.0)
    } else {
        let diff = (b as f64 - c as f64).abs();
        let chi2 = ((diff - 1.0).max(0.0).powi(2)) / (n as f64);
        if chi2 <= 0.00393 {
            0.95
        } else if chi2 < 2.706 {
            0.15
        } else if chi2 < 3.841 {
            0.06
        } else if chi2 < 6.635 {
            0.02
        } else {
            0.001
        }
    }
}

pub fn paired_bootstrap_ci(
    baseline: &[bool],
    candidate: &[bool],
    rounds: usize,
    seed: u64,
) -> (f64, f64, f64) {
    let n = baseline.len();
    if n == 0 || n != candidate.len() {
        return (0.0, 0.0, 0.0);
    }

    let mut rng = SplitMix64::new(seed);
    let mut deltas = Vec::with_capacity(rounds);

    for _ in 0..rounds {
        let mut b_count = 0;
        let mut c_count = 0;
        for _ in 0..n {
            let idx = rng.gen_range(n);
            if baseline[idx] {
                b_count += 1;
            }
            if candidate[idx] {
                c_count += 1;
            }
        }
        let b_rate = b_count as f64 / n as f64;
        let c_rate = c_count as f64 / n as f64;
        deltas.push(c_rate - b_rate);
    }

    deltas.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let low_idx = (rounds as f64 * 0.025) as usize;
    let high_idx = (rounds as f64 * 0.975).min((rounds - 1) as f64) as usize;

    let b_act = baseline.iter().filter(|&&b| b).count() as f64 / n as f64;
    let c_act = candidate.iter().filter(|&&c| c).count() as f64 / n as f64;
    let mean_delta = c_act - b_act;

    (deltas[low_idx], mean_delta, deltas[high_idx])
}
