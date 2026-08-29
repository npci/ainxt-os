// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Statistical methodology for the eval gate (EVAL_PLATFORM.md §5, gap [40]).
//!
//! ADR-010's core failure mode: *"the gate can be satisfied by noise."* A gate that blocks on
//! `candidate_mean < baseline_mean` blocks on coin-flips. This module turns the gate into a
//! **pre-registered, powered, corrected statistical decision**:
//!
//! * **Non-inferiority, not superiority** ([`non_inferiority_test`]) — a change must prove it is *not
//!   meaningfully worse* by more than a pre-registered margin, *at significance*. A null change comes
//!   back "no measured effect", never "regression".
//! * **Effect size + CI** ([`cohens_d`], [`mean_diff_ci`]) — a "significant" but sub-MDE difference is
//!   reported as *no material effect*; significance alone never flaps the gate.
//! * **Power / MDE** ([`power_two_sample`], [`mde_two_sample`]) — a set too small to detect its
//!   pre-registered effect is failed as **underpowered**, not passed with false confidence.
//! * **Paired + CUPED** ([`paired_t_test`], [`cuped_adjust`]) — variance reduction so smaller sets
//!   reach adequate power.
//! * **Multiple-comparison correction** ([`benjamini_hochberg`], [`holm_bonferroni`]) — the gate
//!   watches many `metric × model × category` cells; correction stops both a false block from pure
//!   multiplicity *and* a real regression hiding in the noise of many cells.
//!
//! Everything is pure, deterministic, and std-only. The distribution functions ([`normal_cdf`],
//! [`normal_ppf`], [`student_t_sf`]) are clean-room implementations of standard numerical methods,
//! unit-tested against known reference values so the p-values the gate acts on are trustworthy.

use serde::{Deserialize, Serialize};

// ===========================================================================================
// Distribution primitives (clean-room numerical implementations)
// ===========================================================================================

/// Error function via Abramowitz & Stegun 7.1.26 (|err| < 1.5e-7).
pub fn erf(x: f64) -> f64 {
    let sign = if x < 0.0 { -1.0 } else { 1.0 };
    let x = x.abs();
    let t = 1.0 / (1.0 + 0.3275911 * x);
    let y = 1.0
        - (((((1.061405429 * t - 1.453152027) * t) + 1.421413741) * t - 0.284496736) * t
            + 0.254829592)
            * t
            * (-x * x).exp();
    sign * y
}

/// Standard-normal CDF Φ(x).
pub fn normal_cdf(x: f64) -> f64 {
    0.5 * (1.0 + erf(x / std::f64::consts::SQRT_2))
}

/// Inverse standard-normal CDF (probit) via Acklam's rational approximation
/// (|err| < 1.15e-9 across the central region; refined by one Halley step).
pub fn normal_ppf(p: f64) -> f64 {
    if p <= 0.0 {
        return f64::NEG_INFINITY;
    }
    if p >= 1.0 {
        return f64::INFINITY;
    }
    // The median is exact (0). Return it directly: the Halley refinement below is only as accurate
    // as `normal_cdf`'s erf approximation, which would otherwise nudge the symmetry point off 0.
    if p == 0.5 {
        return 0.0;
    }
    // Coefficients.
    const A: [f64; 6] = [
        -3.969683028665376e+01,
        2.209460984245205e+02,
        -2.759285104469687e+02,
        1.383_577_518_672_69e2,
        -3.066479806614716e+01,
        2.506628277459239e+00,
    ];
    const B: [f64; 5] = [
        -5.447609879822406e+01,
        1.615858368580409e+02,
        -1.556989798598866e+02,
        6.680131188771972e+01,
        -1.328068155288572e+01,
    ];
    const C: [f64; 6] = [
        -7.784894002430293e-03,
        -3.223964580411365e-01,
        -2.400758277161838e+00,
        -2.549732539343734e+00,
        4.374664141464968e+00,
        2.938163982698783e+00,
    ];
    const D: [f64; 4] = [
        7.784695709041462e-03,
        3.224671290700398e-01,
        2.445134137142996e+00,
        3.754408661907416e+00,
    ];
    const P_LOW: f64 = 0.02425;
    const P_HIGH: f64 = 1.0 - P_LOW;

    let x = if p < P_LOW {
        let q = (-2.0 * p.ln()).sqrt();
        (((((C[0] * q + C[1]) * q + C[2]) * q + C[3]) * q + C[4]) * q + C[5])
            / ((((D[0] * q + D[1]) * q + D[2]) * q + D[3]) * q + 1.0)
    } else if p <= P_HIGH {
        let q = p - 0.5;
        let r = q * q;
        (((((A[0] * r + A[1]) * r + A[2]) * r + A[3]) * r + A[4]) * r + A[5]) * q
            / (((((B[0] * r + B[1]) * r + B[2]) * r + B[3]) * r + B[4]) * r + 1.0)
    } else {
        let q = (-2.0 * (1.0 - p).ln()).sqrt();
        -(((((C[0] * q + C[1]) * q + C[2]) * q + C[3]) * q + C[4]) * q + C[5])
            / ((((D[0] * q + D[1]) * q + D[2]) * q + D[3]) * q + 1.0)
    };
    // One Halley refinement step.
    let e = normal_cdf(x) - p;
    let u = e * (2.0 * std::f64::consts::PI).sqrt() * (x * x / 2.0).exp();
    x - u / (1.0 + x * u / 2.0)
}

/// Regularized incomplete beta function I_x(a,b) via the Lentz continued fraction
/// (Numerical-Recipes-style `betacf`). Deterministic; converges for the ranges t-tests need.
fn betai(a: f64, b: f64, x: f64) -> f64 {
    if x <= 0.0 {
        return 0.0;
    }
    if x >= 1.0 {
        return 1.0;
    }
    // bt = x^a (1-x)^b / B(a,b); the same factor in both branches.
    let ln_beta = ln_gamma(a) + ln_gamma(b) - ln_gamma(a + b);
    let bt = (a * x.ln() + b * (1.0 - x).ln() - ln_beta).exp();
    // Use whichever branch converges faster.
    if x < (a + 1.0) / (a + b + 2.0) {
        bt * betacf(a, b, x) / a
    } else {
        1.0 - bt * betacf(b, a, 1.0 - x) / b
    }
}

/// Continued fraction for the incomplete beta (modified Lentz).
fn betacf(a: f64, b: f64, x: f64) -> f64 {
    const MAXIT: usize = 300;
    const EPS: f64 = 3.0e-12;
    const FPMIN: f64 = 1.0e-300;
    let qab = a + b;
    let qap = a + 1.0;
    let qam = a - 1.0;
    let mut c = 1.0;
    let mut d = 1.0 - qab * x / qap;
    if d.abs() < FPMIN {
        d = FPMIN;
    }
    d = 1.0 / d;
    let mut h = d;
    for m in 1..=MAXIT {
        let m = m as f64;
        let m2 = 2.0 * m;
        // even step
        let aa = m * (b - m) * x / ((qam + m2) * (a + m2));
        d = 1.0 + aa * d;
        if d.abs() < FPMIN {
            d = FPMIN;
        }
        c = 1.0 + aa / c;
        if c.abs() < FPMIN {
            c = FPMIN;
        }
        d = 1.0 / d;
        h *= d * c;
        // odd step
        let aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2));
        d = 1.0 + aa * d;
        if d.abs() < FPMIN {
            d = FPMIN;
        }
        c = 1.0 + aa / c;
        if c.abs() < FPMIN {
            c = FPMIN;
        }
        d = 1.0 / d;
        let del = d * c;
        h *= del;
        if (del - 1.0).abs() < EPS {
            break;
        }
    }
    h
}

/// Lanczos approximation of ln Γ(x) for x > 0 (double precision).
fn ln_gamma(x: f64) -> f64 {
    const G: f64 = 7.0;
    const COEF: [f64; 9] = [
        0.999_999_999_999_809_9,
        676.520_368_121_885_1,
        -1_259.139_216_722_402_8,
        771.323_428_777_653_1,
        -176.615_029_162_140_6,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_12,
        9.984_369_578_019_572e-6,
        1.505_632_735_149_311_6e-7,
    ];
    let x = x - 1.0;
    let mut a = COEF[0];
    let t = x + G + 0.5;
    for (i, &c) in COEF.iter().enumerate().skip(1) {
        a += c / (x + i as f64);
    }
    0.5 * (2.0 * std::f64::consts::PI).ln() + (x + 0.5) * t.ln() - t + a.ln()
}

/// Survival function of Student's t with `df` degrees of freedom: P(T > t).
pub fn student_t_sf(t: f64, df: f64) -> f64 {
    if df <= 0.0 {
        return f64::NAN;
    }
    let x = df / (df + t * t);
    let tail = 0.5 * betai(df / 2.0, 0.5, x);
    if t >= 0.0 {
        tail
    } else {
        1.0 - tail
    }
}

/// Two-sided Student's t p-value: P(|T| > |t|).
pub fn student_t_two_sided(t: f64, df: f64) -> f64 {
    2.0 * student_t_sf(t.abs(), df)
}

/// CDF of Student's t: P(T ≤ t).
pub fn student_t_cdf(t: f64, df: f64) -> f64 {
    1.0 - student_t_sf(t, df)
}

// ===========================================================================================
// Samples + summary statistics
// ===========================================================================================

/// Summary of one sample (a group of per-case scores).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct SampleStats {
    pub n: usize,
    pub mean: f64,
    /// Unbiased sample variance (n − 1 denominator). 0 for n < 2.
    pub var: f64,
}

impl SampleStats {
    /// Compute from a slice; `var` uses the n − 1 denominator.
    pub fn from_slice(xs: &[f64]) -> Self {
        let n = xs.len();
        if n == 0 {
            return SampleStats {
                n: 0,
                mean: 0.0,
                var: 0.0,
            };
        }
        let mean = xs.iter().sum::<f64>() / n as f64;
        let var = if n < 2 {
            0.0
        } else {
            xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n as f64 - 1.0)
        };
        SampleStats { n, mean, var }
    }

    pub fn std_dev(&self) -> f64 {
        self.var.sqrt()
    }

    pub fn std_error(&self) -> f64 {
        if self.n == 0 {
            0.0
        } else {
            (self.var / self.n as f64).sqrt()
        }
    }
}

/// The outcome of a two-sample comparison.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct TestResult {
    /// t statistic.
    pub t: f64,
    /// degrees of freedom used for the p-value.
    pub df: f64,
    /// p-value (one- or two-sided depending on the test).
    pub p_value: f64,
}

/// Welch's two-sample t-test (unequal variances), two-sided.
/// Both samples need n ≥ 2 and non-zero total variance.
pub fn welch_t_test(a: &SampleStats, b: &SampleStats) -> Option<TestResult> {
    if a.n < 2 || b.n < 2 {
        return None;
    }
    let va = a.var / a.n as f64;
    let vb = b.var / b.n as f64;
    let se = (va + vb).sqrt();
    if se == 0.0 {
        return None;
    }
    let t = (a.mean - b.mean) / se;
    // Welch-Satterthwaite df.
    let df =
        (va + vb).powi(2) / (va.powi(2) / (a.n as f64 - 1.0) + vb.powi(2) / (b.n as f64 - 1.0));
    Some(TestResult {
        t,
        df,
        p_value: student_t_two_sided(t, df),
    })
}

/// Paired t-test on the per-case differences `candidate - baseline` (default eval design — the same
/// gold cases run through both arms). Far lower variance than an unpaired comparison.
/// Returns the paired mean difference alongside the test.
pub fn paired_t_test(diffs: &[f64]) -> Option<(f64, TestResult)> {
    let n = diffs.len();
    if n < 2 {
        return None;
    }
    let s = SampleStats::from_slice(diffs);
    let se = s.std_error();
    if se == 0.0 {
        return None;
    }
    let t = s.mean / se;
    let df = n as f64 - 1.0;
    Some((
        s.mean,
        TestResult {
            t,
            df,
            p_value: student_t_two_sided(t, df),
        },
    ))
}

// ===========================================================================================
// Non-inferiority — the framing the gate uses (EVAL_PLATFORM.md §5.2)
// ===========================================================================================

/// The gate's verdict on one metric cell.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NonInferiorityVerdict {
    /// The candidate is statistically not worse than baseline by more than the margin: it may ship.
    NonInferior { p_value: f64, effect: f64 },
    /// The candidate is worse than baseline beyond the margin, at significance: a blocking regression.
    Inferior { p_value: f64, effect: f64 },
    /// Not enough data / no variance to decide — honest, never a silent pass.
    Indeterminate(String),
}

impl NonInferiorityVerdict {
    pub fn is_non_inferior(&self) -> bool {
        matches!(self, NonInferiorityVerdict::NonInferior { .. })
    }
    pub fn is_inferior(&self) -> bool {
        matches!(self, NonInferiorityVerdict::Inferior { .. })
    }
}

/// One-sided non-inferiority test for a **higher-is-better** metric using a paired design.
///
/// H0: `mean(candidate − baseline) ≤ −margin` (candidate is materially worse).
/// H1: `mean(candidate − baseline) > −margin` (candidate is non-inferior).
///
/// We reject H0 (declare **non-inferior**) when the lower one-sided p-value of the shifted statistic
/// `(mean_diff + margin) / SE` is below `alpha`. `margin` is in the metric's own units and must be
/// ≥ 0. This is the paired analogue of the classic non-inferiority test.
pub fn non_inferiority_paired(diffs: &[f64], margin: f64, alpha: f64) -> NonInferiorityVerdict {
    if diffs.len() < 2 {
        return NonInferiorityVerdict::Indeterminate(format!(
            "paired sample too small: n={} (need >= 2)",
            diffs.len()
        ));
    }
    let s = SampleStats::from_slice(diffs);
    let se = s.std_error();
    if se == 0.0 {
        // Zero variance: decide purely on whether the observed shift clears −margin.
        return if s.mean + margin > 0.0 || (s.mean >= 0.0) {
            NonInferiorityVerdict::NonInferior {
                p_value: 0.0,
                effect: s.mean,
            }
        } else {
            NonInferiorityVerdict::Inferior {
                p_value: 0.0,
                effect: s.mean,
            }
        };
    }
    let df = s.n as f64 - 1.0;
    // Statistic for H0: (mean_diff - (-margin)) / SE = (mean_diff + margin) / SE.
    let t = (s.mean + margin) / se;
    // One-sided upper p-value: probability of a t this large or larger under H0.
    let p = student_t_sf(t, df);
    if p < alpha {
        NonInferiorityVerdict::NonInferior {
            p_value: p,
            effect: s.mean,
        }
    } else {
        NonInferiorityVerdict::Inferior {
            p_value: p,
            effect: s.mean,
        }
    }
}

// ===========================================================================================
// Effect size + confidence interval (EVAL_PLATFORM.md §5.5)
// ===========================================================================================

/// Cohen's d for two independent samples (pooled SD). Positive = `a` higher than `b`.
pub fn cohens_d(a: &SampleStats, b: &SampleStats) -> Option<f64> {
    if a.n < 2 || b.n < 2 {
        return None;
    }
    let pooled = (((a.n as f64 - 1.0) * a.var + (b.n as f64 - 1.0) * b.var)
        / (a.n as f64 + b.n as f64 - 2.0))
        .sqrt();
    if pooled == 0.0 {
        return None;
    }
    Some((a.mean - b.mean) / pooled)
}

/// Two-sided CI for the difference of means `a − b` at confidence `1 − alpha` (normal approx).
pub fn mean_diff_ci(a: &SampleStats, b: &SampleStats, alpha: f64) -> Option<(f64, f64)> {
    if a.n == 0 || b.n == 0 {
        return None;
    }
    let se = (a.var / a.n as f64 + b.var / b.n as f64).sqrt();
    let z = normal_ppf(1.0 - alpha / 2.0);
    let d = a.mean - b.mean;
    Some((d - z * se, d + z * se))
}

// ===========================================================================================
// Power / MDE (EVAL_PLATFORM.md §5.3) — an underpowered set is a defect
// ===========================================================================================

/// Approximate power of a two-sample (equal-n) two-sided test to detect standardized effect `d`
/// at significance `alpha`, with `n` cases **per arm** (normal approximation).
pub fn power_two_sample(d: f64, n_per_arm: usize, alpha: f64) -> f64 {
    if n_per_arm < 2 {
        return 0.0;
    }
    let z_alpha = normal_ppf(1.0 - alpha / 2.0);
    let ncp = d.abs() * (n_per_arm as f64 / 2.0).sqrt();
    normal_cdf(ncp - z_alpha)
}

/// Minimum detectable standardized effect at the target `power` and significance `alpha` for `n`
/// cases **per arm** (normal approximation) — the inverse of [`power_two_sample`].
pub fn mde_two_sample(n_per_arm: usize, alpha: f64, power: f64) -> f64 {
    if n_per_arm < 2 {
        return f64::INFINITY;
    }
    let z_alpha = normal_ppf(1.0 - alpha / 2.0);
    let z_power = normal_ppf(power);
    (z_alpha + z_power) / (n_per_arm as f64 / 2.0).sqrt()
}

/// Is the set powered enough to detect its pre-registered MDE? `mde_units` and the sample SD are in
/// the metric's own units, converted to a standardized effect internally.
pub fn is_powered(
    n_per_arm: usize,
    sample_sd: f64,
    mde_units: f64,
    alpha: f64,
    target_power: f64,
) -> bool {
    if sample_sd <= 0.0 {
        // No variance — any real effect is trivially detectable.
        return true;
    }
    let d = mde_units / sample_sd;
    power_two_sample(d, n_per_arm, alpha) >= target_power
}

// ===========================================================================================
// CUPED variance reduction (EVAL_PLATFORM.md §5.3)
// ===========================================================================================

/// CUPED-adjust a metric series `y` using a pre-period covariate `x` (per-case difficulty), returning
/// the variance-reduced series `y − θ(x − x̄)` where `θ = cov(x,y)/var(x)`. A larger |correlation|
/// yields a larger variance reduction, letting a smaller set reach adequate power. Falls back to the
/// raw series when `x` has no variance.
pub fn cuped_adjust(y: &[f64], x: &[f64]) -> Vec<f64> {
    let n = y.len();
    if n == 0 || x.len() != n {
        return y.to_vec();
    }
    let xbar = x.iter().sum::<f64>() / n as f64;
    let ybar = y.iter().sum::<f64>() / n as f64;
    let mut cov = 0.0;
    let mut varx = 0.0;
    for (&xi, &yi) in x.iter().zip(y.iter()) {
        cov += (xi - xbar) * (yi - ybar);
        varx += (xi - xbar).powi(2);
    }
    if varx == 0.0 {
        return y.to_vec();
    }
    let theta = cov / varx;
    x.iter()
        .zip(y.iter())
        .map(|(&xi, &yi)| yi - theta * (xi - xbar))
        .collect()
}

// ===========================================================================================
// Multiple-comparison correction (EVAL_PLATFORM.md §5.4)
// ===========================================================================================

/// Benjamini-Hochberg FDR control. Returns, for each input p-value (in input order), whether it is
/// rejected (a discovery) at false-discovery rate `q`. Controls a **false block from multiplicity**
/// and, symmetrically, keeps a real regression from hiding across many cells.
pub fn benjamini_hochberg(pvals: &[f64], q: f64) -> Vec<bool> {
    let m = pvals.len();
    let mut rejected = vec![false; m];
    if m == 0 {
        return rejected;
    }
    // Sort indices by p-value ascending.
    let mut idx: Vec<usize> = (0..m).collect();
    idx.sort_by(|&i, &j| {
        pvals[i]
            .partial_cmp(&pvals[j])
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    // Largest k with p_(k) <= (k/m) q.
    let mut k_max: Option<usize> = None;
    for (rank, &i) in idx.iter().enumerate() {
        let k = rank + 1;
        if pvals[i] <= (k as f64 / m as f64) * q {
            k_max = Some(rank);
        }
    }
    if let Some(kr) = k_max {
        for &i in idx.iter().take(kr + 1) {
            rejected[i] = true;
        }
    }
    rejected
}

/// Holm-Bonferroni family-wise error control (used for the hard-safety subset where any false
/// negative is unacceptable). Returns per-input rejection at family-wise level `alpha`.
pub fn holm_bonferroni(pvals: &[f64], alpha: f64) -> Vec<bool> {
    let m = pvals.len();
    let mut rejected = vec![false; m];
    if m == 0 {
        return rejected;
    }
    let mut idx: Vec<usize> = (0..m).collect();
    idx.sort_by(|&i, &j| {
        pvals[i]
            .partial_cmp(&pvals[j])
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    for (rank, &i) in idx.iter().enumerate() {
        let threshold = alpha / (m - rank) as f64;
        if pvals[i] <= threshold {
            rejected[i] = true;
        } else {
            // Holm stops at the first non-rejection; nothing further can be rejected.
            break;
        }
    }
    rejected
}

// ===========================================================================================
// The statistical gate — per-cell non-inferiority + multiplicity correction (§5.4)
// ===========================================================================================

/// One `metric × model × category` cell under test, as paired per-case diffs `candidate − baseline`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricCell {
    pub name: String,
    /// Per-case paired differences (candidate − baseline). Higher-is-better assumed; negate a
    /// lower-is-better metric before constructing the cell.
    pub diffs: Vec<f64>,
    /// Non-inferiority margin (metric units, ≥ 0).
    pub margin: f64,
    /// Cells in the hard-safety subset (data-class-leak, redaction, RBAC) get family-wise (Holm)
    /// control — any false negative is unacceptable; the rest get FDR (Benjamini-Hochberg).
    pub hard_safety: bool,
}

/// A per-cell verdict from the gate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CellVerdict {
    pub name: String,
    /// Is this cell a blocking regression (worse beyond the margin, significant after correction)?
    pub blocked: bool,
    /// The regression p-value (small = strong evidence of a material regression).
    pub p_regression: f64,
    /// Mean paired difference (candidate − baseline) — the effect size in metric units.
    pub effect: f64,
    /// 95% CI for the mean paired difference.
    pub ci: (f64, f64),
    /// Human-readable note (e.g. "no material effect", "indeterminate: n<2").
    pub note: String,
}

/// The gate's overall report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GateReport {
    pub cells: Vec<CellVerdict>,
}

impl GateReport {
    /// The gate passes iff no cell is a blocking regression.
    pub fn passed(&self) -> bool {
        self.cells.iter().all(|c| !c.blocked)
    }
    /// Names of the blocking cells.
    pub fn blocking(&self) -> Vec<&str> {
        self.cells
            .iter()
            .filter(|c| c.blocked)
            .map(|c| c.name.as_str())
            .collect()
    }
}

/// Regression p-value for one cell: P(mean_diff ≤ observed | boundary mean_diff = −margin). Small
/// when the candidate is materially worse than −margin.
fn regression_p(diffs: &[f64], margin: f64) -> Option<(f64, f64, (f64, f64))> {
    if diffs.len() < 2 {
        return None;
    }
    let s = SampleStats::from_slice(diffs);
    let se = s.std_error();
    let ci_half = normal_ppf(0.975) * se;
    let ci = (s.mean - ci_half, s.mean + ci_half);
    if se == 0.0 {
        // No variance: a deterministic verdict on whether the shift is below −margin.
        let p = if s.mean < -margin { 0.0 } else { 1.0 };
        return Some((p, s.mean, ci));
    }
    let df = s.n as f64 - 1.0;
    // t of the observed mean vs the H0 boundary (−margin).
    let t = (s.mean + margin) / se;
    // Lower-tail probability = evidence the candidate is worse than the boundary.
    let p = student_t_cdf(t, df);
    Some((p, s.mean, ci))
}

/// The statistical gate: run each cell's regression test, then control multiplicity — Benjamini-
/// Hochberg (FDR `q`) across the ordinary cells and Holm-Bonferroni (family-wise `alpha`) across the
/// hard-safety cells — so a cell only *blocks* when its regression survives correction. This is the
/// concrete answer to gap [40] ("the gate can be satisfied by noise"): a null change yields no
/// blocking cell; a genuine regression beyond the margin blocks; pure multiplicity does not.
pub fn statistical_gate(cells: &[MetricCell], alpha: f64, q: f64) -> GateReport {
    // Compute per-cell regression stats.
    struct Row {
        name: String,
        hard: bool,
        p: Option<f64>,
        effect: f64,
        ci: (f64, f64),
    }
    let mut rows: Vec<Row> = Vec::with_capacity(cells.len());
    for c in cells {
        match regression_p(&c.diffs, c.margin) {
            Some((p, effect, ci)) => rows.push(Row {
                name: c.name.clone(),
                hard: c.hard_safety,
                p: Some(p),
                effect,
                ci,
            }),
            None => rows.push(Row {
                name: c.name.clone(),
                hard: c.hard_safety,
                p: None,
                effect: 0.0,
                ci: (0.0, 0.0),
            }),
        }
    }
    // Partition p-values by family, correct each, and map rejections back.
    let mut normal_idx = Vec::new();
    let mut normal_p = Vec::new();
    let mut hard_idx = Vec::new();
    let mut hard_p = Vec::new();
    for (i, r) in rows.iter().enumerate() {
        if let Some(p) = r.p {
            if r.hard {
                hard_idx.push(i);
                hard_p.push(p);
            } else {
                normal_idx.push(i);
                normal_p.push(p);
            }
        }
    }
    let normal_rej = benjamini_hochberg(&normal_p, q);
    let hard_rej = holm_bonferroni(&hard_p, alpha);
    let mut blocked = vec![false; rows.len()];
    for (k, &i) in normal_idx.iter().enumerate() {
        blocked[i] = normal_rej[k];
    }
    for (k, &i) in hard_idx.iter().enumerate() {
        blocked[i] = hard_rej[k];
    }

    let cells_out = rows
        .into_iter()
        .enumerate()
        .map(|(i, r)| {
            let (p, note) = match r.p {
                None => (1.0, "indeterminate: n<2".to_string()),
                Some(p) if blocked[i] => (
                    p,
                    "blocking regression (significant after correction)".to_string(),
                ),
                Some(p) if r.effect >= 0.0 => (p, "no measured regression".to_string()),
                Some(p) => (
                    p,
                    "worse but within margin / not significant after correction".to_string(),
                ),
            };
            CellVerdict {
                name: r.name,
                blocked: blocked[i],
                p_regression: p,
                effect: r.effect,
                ci: r.ci,
                note,
            }
        })
        .collect();
    GateReport { cells: cells_out }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx(a: f64, b: f64, tol: f64) -> bool {
        (a - b).abs() <= tol
    }

    #[test]
    fn erf_and_normal_cdf_match_references() {
        // erf(0)=0, erf(1)=0.8427007929, erf(2)=0.9953222650
        assert!(approx(erf(0.0), 0.0, 1e-9));
        assert!(approx(erf(1.0), 0.842_700_79, 1e-6));
        assert!(approx(erf(-1.0), -0.842_700_79, 1e-6));
        // Φ(0)=0.5, Φ(1.96)≈0.975, Φ(-1.96)≈0.025
        assert!(approx(normal_cdf(0.0), 0.5, 1e-9));
        assert!(approx(normal_cdf(1.96), 0.975, 1e-3));
        assert!(approx(normal_cdf(-1.96), 0.025, 1e-3));
    }

    #[test]
    fn normal_ppf_inverts_cdf() {
        for &p in &[0.01, 0.1, 0.25, 0.5, 0.75, 0.9, 0.975, 0.99] {
            let x = normal_ppf(p);
            assert!(
                approx(normal_cdf(x), p, 1e-6),
                "ppf/cdf round-trip failed at p={p}: cdf(ppf)={}",
                normal_cdf(x)
            );
        }
        // Known quantiles.
        assert!(approx(normal_ppf(0.975), 1.959_964, 1e-4));
        assert!(approx(normal_ppf(0.5), 0.0, 1e-9));
    }

    #[test]
    fn student_t_matches_known_pvalues() {
        // With df=∞, t-dist → normal. Two-sided p at t=1.96, large df ≈ 0.05.
        let p = student_t_two_sided(1.959_964, 100_000.0);
        assert!(approx(p, 0.05, 1e-3), "large-df t two-sided p={p}");
        // df=10, t=2.228 → two-sided p ≈ 0.05 (standard t-table value).
        let p10 = student_t_two_sided(2.228, 10.0);
        assert!(approx(p10, 0.05, 2e-3), "df=10 t=2.228 p={p10}");
        // Symmetry.
        assert!(approx(
            student_t_sf(1.5, 7.0),
            1.0 - student_t_sf(-1.5, 7.0),
            1e-9
        ));
    }

    #[test]
    fn welch_detects_a_real_difference_and_not_noise() {
        // Clearly different means, tight variance → significant.
        let a = SampleStats::from_slice(&[90.0, 91.0, 89.0, 92.0, 90.0, 91.0]);
        let b = SampleStats::from_slice(&[70.0, 71.0, 69.0, 72.0, 70.0, 71.0]);
        let r = welch_t_test(&a, &b).expect("valid samples");
        assert!(
            r.p_value < 0.001,
            "20-point gap must be significant: p={}",
            r.p_value
        );
        // Identical distributions → not significant.
        let c = SampleStats::from_slice(&[80.0, 82.0, 78.0, 81.0, 79.0, 80.0]);
        let d = SampleStats::from_slice(&[80.0, 79.0, 81.0, 82.0, 78.0, 80.0]);
        let r2 = welch_t_test(&c, &d).expect("valid");
        assert!(
            r2.p_value > 0.2,
            "no real difference must not be significant: p={}",
            r2.p_value
        );
    }

    #[test]
    fn non_inferiority_passes_null_and_blocks_regression() {
        // Null change: paired diffs centered on 0 with small noise → NON-inferior (didn't regress).
        let null_diffs = vec![0.5, -0.5, 0.3, -0.2, 0.1, -0.1, 0.4, -0.3];
        let v = non_inferiority_paired(&null_diffs, 2.0, 0.05);
        assert!(
            v.is_non_inferior(),
            "a null change must pass non-inferiority: {v:?}"
        );

        // Real regression: every case dropped ~8 points, margin 2 → INFERIOR (blocks).
        let reg_diffs = vec![-8.0, -7.5, -8.5, -7.0, -9.0, -8.0, -7.8, -8.2];
        let v2 = non_inferiority_paired(&reg_diffs, 2.0, 0.05);
        assert!(
            v2.is_inferior(),
            "an 8-point regression beyond a 2-point margin must block: {v2:?}"
        );
    }

    #[test]
    fn non_inferiority_indeterminate_on_thin_data() {
        let v = non_inferiority_paired(&[1.0], 2.0, 0.05);
        assert!(matches!(v, NonInferiorityVerdict::Indeterminate(_)));
    }

    #[test]
    fn cohens_d_and_ci_are_sane() {
        let a = SampleStats::from_slice(&[10.0, 12.0, 11.0, 13.0, 9.0]);
        let b = SampleStats::from_slice(&[5.0, 6.0, 4.0, 7.0, 5.0]);
        let d = cohens_d(&a, &b).expect("valid");
        assert!(d > 2.0, "a large mean gap should give a large d: {d}");
        let (lo, hi) = mean_diff_ci(&a, &b, 0.05).expect("valid");
        assert!(
            lo > 0.0 && hi > lo,
            "CI for a positive diff should be positive: [{lo},{hi}]"
        );
        assert!(
            lo < a.mean - b.mean && a.mean - b.mean < hi,
            "CI must contain the point estimate"
        );
    }

    #[test]
    fn power_and_mde_are_consistent() {
        // A medium effect (d=0.5) with a decent n should be well-powered.
        let p = power_two_sample(0.5, 64, 0.05);
        assert!(p > 0.8, "d=0.5, n=64/arm should exceed 0.8 power: {p}");
        // Tiny n → underpowered for the same effect.
        let p_small = power_two_sample(0.5, 8, 0.05);
        assert!(
            p_small < 0.5,
            "d=0.5, n=8/arm should be underpowered: {p_small}"
        );
        // MDE at 0.8 power should round-trip: power at the MDE ≈ 0.8.
        let mde = mde_two_sample(64, 0.05, 0.8);
        assert!(
            approx(power_two_sample(mde, 64, 0.05), 0.8, 0.02),
            "MDE inverse: {mde}"
        );
    }

    #[test]
    fn underpowered_set_is_flagged() {
        // sd=15, want to detect a 3-point MDE with only 10 cases/arm → underpowered.
        assert!(!is_powered(10, 15.0, 3.0, 0.05, 0.8));
        // 800 cases/arm makes the same 3-point MDE detectable.
        assert!(is_powered(800, 15.0, 3.0, 0.05, 0.8));
    }

    #[test]
    fn cuped_reduces_variance_when_covariate_correlates() {
        // y strongly correlated with pre-period covariate x plus a small treatment shift.
        let x: Vec<f64> = (0..40).map(|i| i as f64).collect();
        let y: Vec<f64> = x.iter().map(|&xi| 2.0 * xi + 3.0).collect();
        let adj = cuped_adjust(&y, &x);
        let var_raw = SampleStats::from_slice(&y).var;
        let var_adj = SampleStats::from_slice(&adj).var;
        assert!(
            var_adj < var_raw * 0.01,
            "CUPED must slash variance when y≈f(x): raw={var_raw}, adj={var_adj}"
        );
    }

    #[test]
    fn cuped_no_covariate_variance_is_identity() {
        let y = vec![1.0, 2.0, 3.0];
        let x = vec![5.0, 5.0, 5.0];
        assert_eq!(cuped_adjust(&y, &x), y);
    }

    #[test]
    fn benjamini_hochberg_controls_fdr() {
        // Three tiny p-values (real) + many large ones (null). BH should reject the tiny ones.
        // At m=100, α=0.05 the rank-k threshold is k·0.0005, so the discoveries must be well below
        // that (0.001 would NOT be significant at rank 1 — 0.001 > 0.0005 — the earlier values were
        // a test bug, not an impl bug).
        let mut pvals = vec![1e-5, 2e-5, 3e-5];
        pvals.extend(std::iter::repeat_n(0.8, 97));
        let rej = benjamini_hochberg(&pvals, 0.05);
        assert!(
            rej[0] && rej[1] && rej[2],
            "clear discoveries must be rejected"
        );
        assert!(
            rej.iter().skip(3).all(|&r| !r),
            "null cells must not be discoveries"
        );
        // All-null: nothing rejected.
        let allnull = vec![0.4, 0.5, 0.6, 0.7];
        assert!(benjamini_hochberg(&allnull, 0.05).iter().all(|&r| !r));
    }

    #[test]
    fn holm_is_more_conservative_than_bh() {
        // A borderline set where BH rejects more than Holm.
        let pvals = vec![0.01, 0.02, 0.03, 0.04, 0.05];
        let bh = benjamini_hochberg(&pvals, 0.05);
        let holm = holm_bonferroni(&pvals, 0.05);
        let bh_count = bh.iter().filter(|&&r| r).count();
        let holm_count = holm.iter().filter(|&&r| r).count();
        assert!(
            holm_count <= bh_count,
            "Holm (FWER) must reject no more than BH (FDR): holm={holm_count}, bh={bh_count}"
        );
    }

    #[test]
    fn statistical_gate_blocks_regression_passes_noise() {
        // A genuine regression cell: every case ~8 below, tight, margin 2 → should block.
        let regression = MetricCell {
            name: "correctness".into(),
            diffs: vec![-8.0, -7.5, -8.5, -7.0, -9.0, -8.0, -7.8, -8.2, -8.1, -7.9],
            margin: 2.0,
            hard_safety: false,
        };
        // A null cell: centered on 0 with noise → must NOT block.
        let null = MetricCell {
            name: "tone".into(),
            diffs: vec![0.5, -0.5, 0.3, -0.2, 0.1, -0.1, 0.4, -0.3, 0.2, -0.2],
            margin: 2.0,
            hard_safety: false,
        };
        let report = statistical_gate(&[regression, null], 0.05, 0.05);
        assert!(!report.passed(), "a real regression must block the gate");
        assert!(report.blocking().contains(&"correctness"));
        assert!(
            !report.blocking().contains(&"tone"),
            "a null cell must not block"
        );
    }

    #[test]
    fn statistical_gate_does_not_flap_on_pure_multiplicity() {
        // 50 null cells (each centered on 0, noisy). Without correction, some would look "worse" by
        // chance; BH/Holm must keep the gate green.
        let mut cells = Vec::new();
        for i in 0..50 {
            // Deterministic pseudo-noise around 0 via a fixed pattern per cell.
            let base = ((i * 7) % 5) as f64 - 2.0; // in [-2, 2]
            let diffs: Vec<f64> = (0..12)
                .map(|k| {
                    let s = if (i + k) % 2 == 0 { 1.0 } else { -1.0 };
                    base * 0.1 + s * ((k % 3) as f64 - 1.0) * 0.5
                })
                .collect();
            cells.push(MetricCell {
                name: format!("cell-{i}"),
                diffs,
                margin: 3.0,
                hard_safety: false,
            });
        }
        let report = statistical_gate(&cells, 0.05, 0.05);
        assert!(
            report.passed(),
            "50 null cells must not flap the gate: blocking={:?}",
            report.blocking()
        );
    }

    #[test]
    fn hard_safety_cells_use_family_wise_control() {
        // A hard-safety regression cell must still block; it goes through Holm, not BH.
        let leak = MetricCell {
            name: "data-class-leak".into(),
            diffs: vec![-10.0, -9.0, -11.0, -10.5, -9.5, -10.0, -10.2, -9.8],
            margin: 1.0,
            hard_safety: true,
        };
        let report = statistical_gate(&[leak], 0.05, 0.05);
        assert!(!report.passed(), "a hard-safety regression must block");
        assert!(report.blocking().contains(&"data-class-leak"));
    }

    #[test]
    fn gate_report_serializes() {
        let c = MetricCell {
            name: "x".into(),
            diffs: vec![1.0, 2.0, 3.0],
            margin: 1.0,
            hard_safety: false,
        };
        let r = statistical_gate(&[c], 0.05, 0.05);
        let j = serde_json::to_string(&r).unwrap();
        let back: GateReport = serde_json::from_str(&j).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn paired_test_has_more_power_than_unpaired() {
        // Same data, paired vs unpaired: the paired analysis yields a smaller p-value because the
        // per-case correlation cancels. baseline high, candidate a hair lower but correlated.
        let baseline = [80.0, 60.0, 90.0, 70.0, 85.0, 65.0, 95.0, 75.0];
        // A small, per-case-varying uplift (diffs 2,3,1,3,1,3,1,2 — mean exactly 2, low variance).
        let candidate = [82.0, 63.0, 91.0, 73.0, 86.0, 68.0, 96.0, 77.0];
        let diffs: Vec<f64> = candidate
            .iter()
            .zip(baseline.iter())
            .map(|(c, b)| c - b)
            .collect();
        let (mean_d, paired) = paired_t_test(&diffs).expect("valid");
        assert!(
            approx(mean_d, 2.0, 1e-9),
            "mean diff should be exactly 2: {mean_d}"
        );
        let a = SampleStats::from_slice(&candidate);
        let b = SampleStats::from_slice(&baseline);
        let unpaired = welch_t_test(&a, &b).expect("valid");
        assert!(
            paired.p_value < unpaired.p_value,
            "paired must be more powerful: paired p={}, unpaired p={}",
            paired.p_value,
            unpaired.p_value
        );
    }
}
