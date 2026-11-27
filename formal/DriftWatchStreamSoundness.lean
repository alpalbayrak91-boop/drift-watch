-- SPDX-FileCopyrightText: 2026 Alp Albayrak
-- SPDX-License-Identifier: MIT
-- Drift-Watch v4.0.0 — Pure-Init Lean 4 Formal Soundness Kernel (Part 2: Streaming & Contract Invariants)
-- Zero external dependencies (Init only); verified with `lean --trust=0 -DwarningAsError=true`.

set_option autoImplicit false
set_option warningAsError true

namespace DriftWatch.StreamSoundness

def unscopedPairChanged (a1 a2 b1 b2 : Nat) : Bool :=
  !((a1 == b1 && a2 == b2) || (a1 == b2 && a2 == b1))

def freeClauseTightened (freeBase freeCurr : Nat) : Bool :=
  decide (freeCurr < freeBase)

def polarityHazardActive (phraseMatched hasNegationWindow : Bool) : Bool :=
  phraseMatched && (!hasNegationWindow)

def stepTightened10Pct (refCap curCap : Nat) : Bool :=
  decide (curCap * 10 ≤ refCap * 9)

def adaptiveOrderQBps (lam1Bps : Int) : Int :=
  if 2 * (10000 - lam1Bps) ≤ 1000 then 1000 else 2 * (10000 - lam1Bps)

def alertHingeBudgetCents (baseCents rateCents inclAlerts alertCount : Nat) : Nat :=
  baseCents + rateCents * (alertCount - inclAlerts)

def corroborationQuorum (n f : Nat) : Nat :=
  if 3 ≤ n - f then n - f else 3

def streamCrossPairs : List Int → Int
  | [] => 0
  | d :: ds =>
      let prev := streamCrossPairs ds
      let tailSum := ds.foldl (· + ·) 0
      prev + d * tailSum

private theorem foldSumAddInit (ds : List Int) (init : Int) :
    ds.foldl (· + ·) init = init + ds.foldl (· + ·) 0 := by
  induction ds generalizing init with
  | nil =>
    simp
  | cons x xs ih =>
    simp only [List.foldl]
    rw [ih (init + x), ih (0 + x)]
    omega

def streamMmdOnline (ds : List Int) : Int × Int :=
  ds.foldr (fun d st => (st.1 + d * st.2, d + st.2)) (0, 0)

def releaseGateCore (df da dq : Int) : Int :=
  4000 + df + da + (dq / 50)
    + 2 * ((df / 25) * (da / 25))
    + 2 * ((df / 25) * (dq / 4500))
    + 2 * ((da / 25) * (dq / 4500))

def releaseGateBps (clauseScopedOk quorumOk driftF1Bps mmdAurocBps throughputBps : Int) : Int :=
  if clauseScopedOk < 0 ∨ clauseScopedOk > 1 ∨ quorumOk < 0 ∨ quorumOk > 1 ∨
     driftF1Bps < 0 ∨ driftF1Bps > 10000 ∨ mmdAurocBps < 0 ∨ mmdAurocBps > 10000 ∨
     throughputBps < 0 ∨ throughputBps > 120000 then
    -29000
  else if clauseScopedOk ≠ 1 ∨ quorumOk ≠ 1 ∨ driftF1Bps < 9500 ∨ mmdAurocBps < 9500 ∨ throughputBps < 30000 then
    -26000
  else
    releaseGateCore (driftF1Bps - 9500) (mmdAurocBps - 9500) (throughputBps - 30000)

theorem S01_unscoped_setdiff_blind_to_tier_swap :
    unscopedPairChanged 1500 250 250 1500 = false ∧
    freeClauseTightened 1500 250 = true := by
  decide

theorem S02_directional_quota_lattice_asymmetry
    (baseCap currCap : Nat) (hExp : baseCap < currCap) :
    freeClauseTightened baseCap currCap = false ∧
    freeClauseTightened currCap baseCap = true := by
  unfold freeClauseTightened
  refine ⟨?_, ?_⟩
  · simp [decide_eq_false_iff_not]
    omega
  · simp [decide_eq_true_eq]
    omega

theorem S03_negation_window_blocks_assurance_false_positive (p : Bool) :
    polarityHazardActive p true = false ∧
    polarityHazardActive true false = true := by
  cases p <;> decide

theorem S04_dual_anchor_catches_gradual_erosion :
    stepTightened10Pct 1000 920 = false ∧
    stepTightened10Pct 920 850 = false ∧
    stepTightened10Pct 850 785 = false ∧
    stepTightened10Pct 785 715 = false ∧
    stepTightened10Pct 1000 715 = true := by
  decide

theorem S05_sliding_window_sum_exact_conservation (s0 z1 z2 z3 : Int) :
    ((s0 + z2 - z1) + z3 - z2) = s0 + z3 - z1 := by
  omega

def rollingTelescope : Int → List (Int × Int) → Int
  | s, [] => s
  | s, (enterVal, exitVal) :: rest => rollingTelescope (s + enterVal - exitVal) rest

theorem S06_sliding_window_multi_step_telescope
    (s : Int) (steps : List (Int × Int)) :
    rollingTelescope s steps =
      s + (steps.map Prod.fst).foldl (· + ·) 0 - (steps.map Prod.snd).foldl (· + ·) 0 := by
  induction steps generalizing s with
  | nil =>
    simp [rollingTelescope]
  | cons hd tl ih =>
    rcases hd with ⟨en, ex⟩
    simp only [rollingTelescope, List.map, List.foldl]
    rw [ih (s + en - ex)]
    rw [foldSumAddInit (tl.map Prod.fst) (0 + en)]
    rw [foldSumAddInit (tl.map Prod.snd) (0 + ex)]
    omega

theorem S07_adaptive_spectral_order_bounds_and_antitonicity
    (lA lB : Int)
    (hA : 0 ≤ lA ∧ lA ≤ 10000)
    (hB : 0 ≤ lB ∧ lB ≤ 10000)
    (hLe : lA ≤ lB) :
    1000 ≤ adaptiveOrderQBps lA ∧
    adaptiveOrderQBps lA ≤ 20000 ∧
    adaptiveOrderQBps lB ≤ adaptiveOrderQBps lA := by
  refine ⟨?_, ?_, ?_⟩
  · unfold adaptiveOrderQBps
    split <;> omega
  · unfold adaptiveOrderQBps
    split <;> omega
  · unfold adaptiveOrderQBps
    split <;> split <;> omega

theorem S08_centered_perturbation_zero_sum
    (q1 q2 q3 q4 trMean : Int)
    (hMean : q1 + q2 + q3 + q4 = 4 * trMean) :
    (q1 - trMean) + (q2 - trMean) + (q3 - trMean) + (q4 - trMean) = 0 := by
  omega

theorem S09_martingale_mmd_incremental_bilinear_identity (d1 d2 d3 : Int) :
    d1 * d2 + (d1 + d2) * d3 = d1 * d2 + d1 * d3 + d2 * d3 := by
  rw [Int.add_mul]
  omega

theorem S10_martingale_mmd_inductive_prefix_sum (ds : List Int) :
    (streamMmdOnline ds).1 = streamCrossPairs ds ∧
    (streamMmdOnline ds).2 = ds.foldl (· + ·) 0 := by
  induction ds with
  | nil =>
    simp [streamMmdOnline, streamCrossPairs]
  | cons d rest ih =>
    rcases ih with ⟨ih1, ih2⟩
    unfold streamMmdOnline at ih1 ih2 ⊢
    simp only [List.foldr, streamCrossPairs, List.foldl]
    rw [ih1, ih2, foldSumAddInit rest (0 + d)]
    refine ⟨rfl, ?_⟩
    omega

theorem S11_martingale_mmd_exchangeable_antisymmetry (mPrev xCur yRef : Int) :
    mPrev * (xCur - yRef) + mPrev * (yRef - xCur) = 0 := by
  have hZero : (xCur - yRef) + (yRef - xCur) = 0 := by omega
  have hFact : mPrev * (xCur - yRef) + mPrev * (yRef - xCur) =
      mPrev * ((xCur - yRef) + (yRef - xCur)) :=
    (Int.mul_add mPrev (xCur - yRef) (yRef - xCur)).symm
  rw [hFact, hZero, Int.mul_zero]

theorem S12_hinge_alert_budget_subadditivity
    (baseCents rateCents incl d1 d2 : Nat)
    (hArb : incl * rateCents ≤ baseCents) :
    alertHingeBudgetCents baseCents rateCents incl (d1 + d2) ≤
      alertHingeBudgetCents baseCents rateCents incl d1 +
      alertHingeBudgetCents baseCents rateCents incl d2 := by
  unfold alertHingeBudgetCents
  have hSub : (d1 + d2) - incl ≤ (d1 - incl) + (d2 - incl) + incl := by omega
  have hMul : rateCents * ((d1 + d2) - incl) ≤ rateCents * ((d1 - incl) + (d2 - incl) + incl) :=
    Nat.mul_le_mul_left rateCents hSub
  rw [Nat.mul_add, Nat.mul_add, Nat.mul_comm rateCents incl] at hMul
  omega

theorem S13_byzantine_quorum_intersection_safety
    (n f : Nat) (hBft : 3 * f + 1 ≤ n) :
    3 ≤ corroborationQuorum n f ∧
    f + 1 + n ≤ 2 * corroborationQuorum n f := by
  refine ⟨?_, ?_⟩
  · unfold corroborationQuorum; split <;> omega
  · unfold corroborationQuorum; split <;> omega

theorem S14_drift_gate_fail_closed_and_bounded
    (f a q : Int)
    (hF : 9500 ≤ f ∧ f ≤ 10000)
    (hA : 9500 ≤ a ∧ a ≤ 10000)
    (hQ : 30000 ≤ q ∧ q ≤ 120000) :
    releaseGateBps 0 1 f a q = -26000 ∧
    releaseGateBps 1 0 f a q = -26000 ∧
    4000 ≤ releaseGateBps 1 1 f a q ∧
    releaseGateBps 1 1 f a q ≤ 9200 := by
  unfold releaseGateBps
  refine ⟨?_, ?_, ?_, ?_⟩
  · split
    · exfalso; omega
    · split
      · rfl
      · exfalso; omega
  · split
    · exfalso; omega
    · split
      · rfl
      · exfalso; omega
  · split
    · exfalso; omega
    · split
      · exfalso; omega
      · unfold releaseGateCore
        have hDf : 0 ≤ (f - 9500) / 25 := by omega
        have hDa : 0 ≤ (a - 9500) / 25 := by omega
        have hDq : 0 ≤ (q - 30000) / 4500 := by omega
        have hP1 : 0 ≤ ((f - 9500) / 25) * ((a - 9500) / 25) := Int.mul_nonneg hDf hDa
        have hP2 : 0 ≤ ((f - 9500) / 25) * ((q - 30000) / 4500) := Int.mul_nonneg hDf hDq
        have hP3 : 0 ≤ ((a - 9500) / 25) * ((q - 30000) / 4500) := Int.mul_nonneg hDa hDq
        omega
  · split
    · exfalso; omega
    · split
      · exfalso; omega
      · unfold releaseGateCore
        have hDf0 : 0 ≤ (f - 9500) / 25 := by omega
        have hDa0 : 0 ≤ (a - 9500) / 25 := by omega
        have hDq0 : 0 ≤ (q - 30000) / 4500 := by omega
        have hDf20 : (f - 9500) / 25 ≤ 20 := by omega
        have hDa20 : (a - 9500) / 25 ≤ 20 := by omega
        have hDq20 : (q - 30000) / 4500 ≤ 20 := by omega
        have hM1 : ((f - 9500) / 25) * ((a - 9500) / 25) ≤ 20 * 20 :=
          Int.le_trans (Int.mul_le_mul_of_nonneg_right hDf20 hDa0) (by omega)
        have hM2 : ((f - 9500) / 25) * ((q - 30000) / 4500) ≤ 20 * 20 :=
          Int.le_trans (Int.mul_le_mul_of_nonneg_right hDf20 hDq0) (by omega)
        have hM3 : ((a - 9500) / 25) * ((q - 30000) / 4500) ≤ 20 * 20 :=
          Int.le_trans (Int.mul_le_mul_of_nonneg_right hDa20 hDq0) (by omega)
        omega

theorem S15_drift_gate_discrete_supermodularity
    (f a q : Int)
    (hF : 9500 ≤ f ∧ f ≤ 9975)
    (hA : 9500 ≤ a ∧ a ≤ 9975)
    (hQ : 30000 ≤ q ∧ q ≤ 115500) :
    releaseGateBps 1 1 (f + 25) (a + 25) q - releaseGateBps 1 1 (f + 25) a q -
      releaseGateBps 1 1 f (a + 25) q + releaseGateBps 1 1 f a q = 2 ∧
    releaseGateBps 1 1 (f + 25) a (q + 4500) - releaseGateBps 1 1 (f + 25) a q -
      releaseGateBps 1 1 f a (q + 4500) + releaseGateBps 1 1 f a q = 2 ∧
    releaseGateBps 1 1 f (a + 25) (q + 4500) - releaseGateBps 1 1 f (a + 25) q -
      releaseGateBps 1 1 f a (q + 4500) + releaseGateBps 1 1 f a q = 2 := by
  have hUnfold : ∀ x y z, 9500 ≤ x → x ≤ 10000 → 9500 ≤ y → y ≤ 10000 → 30000 ≤ z → z ≤ 120000 →
      releaseGateBps 1 1 x y z = releaseGateCore (x - 9500) (y - 9500) (z - 30000) := by
    intro x y z hx1 hx2 hy1 hy2 hz1 hz2
    unfold releaseGateBps
    split
    · exfalso; omega
    · split
      · exfalso; omega
      · rfl
  have e00 := hUnfold f a q hF.1 (by omega) hA.1 (by omega) hQ.1 (by omega)
  have e10 := hUnfold (f + 25) a q (by omega) (by omega) hA.1 (by omega) hQ.1 (by omega)
  have e01 := hUnfold f (a + 25) q hF.1 (by omega) (by omega) (by omega) hQ.1 (by omega)
  have e11 := hUnfold (f + 25) (a + 25) q (by omega) (by omega) (by omega) (by omega) hQ.1 (by omega)
  have e0q := hUnfold f a (q + 4500) hF.1 (by omega) hA.1 (by omega) (by omega) (by omega)
  have e1q := hUnfold (f + 25) a (q + 4500) (by omega) (by omega) hA.1 (by omega) (by omega) (by omega)
  have eaq := hUnfold f (a + 25) (q + 4500) hF.1 (by omega) (by omega) (by omega) (by omega) (by omega)
  rw [e00, e10, e01, e11, e0q, e1q, eaq]
  unfold releaseGateCore
  have hDivF : (f + 25 - 9500) / 25 = (f - 9500) / 25 + 1 := by omega
  have hDivA : (a + 25 - 9500) / 25 = (a - 9500) / 25 + 1 := by omega
  have hDivQ50 : (q + 4500 - 30000) / 50 = (q - 30000) / 50 + 90 := by omega
  have hDivQ45 : (q + 4500 - 30000) / 4500 = (q - 30000) / 4500 + 1 := by omega
  rw [hDivF, hDivA, hDivQ50, hDivQ45]
  simp only [Int.add_mul, Int.mul_add, Int.one_mul, Int.mul_one]
  omega

#print axioms S01_unscoped_setdiff_blind_to_tier_swap
#print axioms S02_directional_quota_lattice_asymmetry
#print axioms S03_negation_window_blocks_assurance_false_positive
#print axioms S04_dual_anchor_catches_gradual_erosion
#print axioms S05_sliding_window_sum_exact_conservation
#print axioms S06_sliding_window_multi_step_telescope
#print axioms S07_adaptive_spectral_order_bounds_and_antitonicity
#print axioms S08_centered_perturbation_zero_sum
#print axioms S09_martingale_mmd_incremental_bilinear_identity
#print axioms S10_martingale_mmd_inductive_prefix_sum
#print axioms S11_martingale_mmd_exchangeable_antisymmetry
#print axioms S12_hinge_alert_budget_subadditivity
#print axioms S13_byzantine_quorum_intersection_safety
#print axioms S14_drift_gate_fail_closed_and_bounded
#print axioms S15_drift_gate_discrete_supermodularity

end DriftWatch.StreamSoundness
