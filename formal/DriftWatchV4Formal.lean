-- SPDX-FileCopyrightText: 2026 Alp Albayrak
-- SPDX-License-Identifier: MIT
-- Drift-Watch v4.0.0 — Pure-Init Lean 4 Formal Soundness Kernel (Part 1: Core Engine)
-- Zero external dependencies (Init only); verified with `lean --trust=0 -DwarningAsError=true`.

set_option autoImplicit false
set_option warningAsError true

namespace DriftWatch.Formal

-- ============================================================================
-- 1. Coprime Modular Weyl Phase Scheduler & RFC 9110 HTTP 304 Egress Accounting
-- ============================================================================

def weylSlotGen (modulus step offset idx : Nat) : Nat :=
  (idx * step + offset) % modulus

def weylSlot288 (idx : Nat) : Nat :=
  weylSlotGen 288 167 1 idx

def weylOffsetMin1440 (idx : Nat) : Nat :=
  5 * weylSlot288 idx

theorem T01_bezout_coprime_167_288 : (167 * 119) % 288 = 1 := by
  decide

private theorem coprime_step_diff_zero
    (m step inv offset j d : Nat)
    (hcop : (step * inv) % m = 1)
    (hd : d < m)
    (heq : ((j + d) * step + offset) % m = (j * step + offset) % m) :
    d = 0 := by
  let a := j * step + offset
  let b := (j + d) * step + offset
  have hb_eq : b = a + d * step := by
    dsimp [a, b]
    rw [Nat.add_mul]
    omega
  have ha_div : m * (a / m) + a % m = a := Nat.div_add_mod a m
  have hb_div : m * (b / m) + b % m = b := Nat.div_add_mod b m
  have hmod_eq : b % m = a % m := heq
  have hle_ab : a ≤ b := by omega
  have hdiv_ge : a / m ≤ b / m := Nat.div_le_div_right hle_ab
  let q := b / m - a / m
  have hmul_q : m * q = m * (b / m) - m * (a / m) := Nat.mul_sub_left_distrib m (b / m) (a / m)
  have hd_step : d * step = m * q := by omega
  have hmul_inv : d * (step * inv) = m * (q * inv) := by
    calc
      d * (step * inv) = (d * step) * inv := (Nat.mul_assoc d step inv).symm
      _ = (m * q) * inv := by rw [hd_step]
      _ = m * (q * inv) := Nat.mul_assoc m q inv
  have hcop_div : m * ((step * inv) / m) + (step * inv) % m = step * inv :=
    Nat.div_add_mod (step * inv) m
  let k := (step * inv) / m
  have hsi : step * inv = m * k + 1 := by
    dsimp [k]
    omega
  have hexp : d + m * (d * k) = m * (q * inv) := by
    have h1 : d * (m * k + 1) = m * (q * inv) := by
      rw [← hsi]
      exact hmul_inv
    have h2 : d * (m * k + 1) = d * (m * k) + d := by
      rw [Nat.mul_add, Nat.mul_one]
    have h3 : d * (m * k) = m * (d * k) := by
      rw [← Nat.mul_assoc, Nat.mul_comm d m, Nat.mul_assoc]
    omega
  have hmod_lhs : (d + m * (d * k)) % m = d := by
    rw [Nat.add_mul_mod_self_left]
    exact Nat.mod_eq_of_lt hd
  have hmod_rhs : (m * (q * inv)) % m = 0 := Nat.mul_mod_right m (q * inv)
  have hcongr := congrArg (fun z => z % m) hexp
  rw [hmod_lhs, hmod_rhs] at hcongr
  exact hcongr

-- General number-theoretic Weyl coprime slot bijection injectivity
theorem T02_general_coprime_weyl_injective
    (m step inv offset i j : Nat)
    (hcop : (step * inv) % m = 1)
    (hi : i < m) (hj : j < m)
    (heq : weylSlotGen m step offset i = weylSlotGen m step offset j) :
    i = j := by
  unfold weylSlotGen at heq
  rcases Nat.le_total j i with hji | hij
  · have hi_split : j + (i - j) = i := Nat.add_sub_of_le hji
    have hd_lt : i - j < m := by omega
    rw [← hi_split] at heq
    have hz := coprime_step_diff_zero m step inv offset j (i - j) hcop hd_lt heq
    omega
  · have hj_split : i + (j - i) = j := Nat.add_sub_of_le hij
    have hd_lt : j - i < m := by omega
    have heq_sym := heq.symm
    rw [← hj_split] at heq_sym
    have hz := coprime_step_diff_zero m step inv offset i (j - i) hcop hd_lt heq_sym
    omega

theorem T03_weyl_slot_288_collision_free (i j : Nat)
    (hi : i < 288) (hj : j < 288)
    (heq : weylSlot288 i = weylSlot288 j) : i = j :=
  T02_general_coprime_weyl_injective 288 167 119 1 i j T01_bezout_coprime_167_288 hi hj heq

theorem T04_weyl_offset_1440_collision_free (i j : Nat)
    (hi : i < 288) (hj : j < 288)
    (heq : weylOffsetMin1440 i = weylOffsetMin1440 j) : i = j := by
  unfold weylOffsetMin1440 at heq
  have hslot : weylSlot288 i = weylSlot288 j := by omega
  exact T03_weyl_slot_288_collision_free i j hi hj hslot

theorem T05_weyl_offset_in_day_and_5min_aligned (i : Nat) :
    weylOffsetMin1440 i < 1440 ∧ weylOffsetMin1440 i % 5 = 0 := by
  unfold weylOffsetMin1440
  have hslt : weylSlot288 i < 288 := by
    unfold weylSlot288 weylSlotGen
    exact Nat.mod_lt (i * 167 + 1) (by decide)
  refine ⟨?_, Nat.mul_mod_right 5 (weylSlot288 i)⟩
  have hmul : 5 * weylSlot288 i < 5 * 288 := Nat.mul_lt_mul_of_pos_left hslt (by decide)
  exact hmul

def driftBench50HourCount (h : Nat) : Nat :=
  ((List.range 50).filter (fun i => weylOffsetMin1440 i / 60 == h)).length

def allHoursMinimaxBalanced : Bool :=
  (List.range 24).all (fun h =>
    let c := driftBench50HourCount h
    decide (2 ≤ c ∧ c ≤ 3))

theorem T06_driftbench50_hourly_minimax_dispersion : allHoursMinimaxBalanced = true := by
  decide

def http304ActualEgress (wireBytes fullBytes : Nat) (is304 : Bool) : Nat :=
  if is304 then wireBytes else max wireBytes fullBytes

def http304SavedBytes (wireBytes fullBytes : Nat) (is304 : Bool) : Nat :=
  max wireBytes fullBytes - http304ActualEgress wireBytes fullBytes is304

theorem T07_http304_egress_strictly_bounded_and_saved
    (wireBytes fullBytes : Nat) (is304 : Bool) (hle : wireBytes ≤ fullBytes) :
    http304ActualEgress wireBytes fullBytes is304 ≤ fullBytes ∧
    http304ActualEgress wireBytes fullBytes is304 + http304SavedBytes wireBytes fullBytes is304 = fullBytes := by
  have hmax : max wireBytes fullBytes = fullBytes := Nat.max_eq_right hle
  cases is304
  · simp [http304ActualEgress, http304SavedBytes, hmax]
  · simp [http304ActualEgress, http304SavedBytes, hmax, hle, Nat.add_sub_of_le hle]

-- ============================================================================
-- 2. Lorden (1971) / Moustakides (1986) Two-Sided CUSUM & Burst Corroboration
-- ============================================================================

def cusumStepPos (s x mu0 k : Int) : Int :=
  if s + (x - mu0 - k) ≤ 0 then 0 else s + (x - mu0 - k)

def cusumStepNeg (s x mu0 k : Int) : Int :=
  if s + (mu0 - x - k) ≤ 0 then 0 else s + (mu0 - x - k)

def cusumFoldPos (mu0 k : Int) : Int → List Int → Int
  | s, [] => s
  | s, x :: xs => cusumFoldPos mu0 k (cusumStepPos s x mu0 k) xs

def cusumFoldNeg (mu0 k : Int) : Int → List Int → Int
  | s, [] => s
  | s, x :: xs => cusumFoldNeg mu0 k (cusumStepNeg s x mu0 k) xs

def cusumAlarmAt (thresh score : Int) : Bool :=
  decide (thresh ≤ score)

theorem T08_cusum_nonneg_invariant (mu0 k : Int) (xs : List Int) (s : Int) (hs : 0 ≤ s) :
    0 ≤ cusumFoldPos mu0 k s xs ∧ 0 ≤ cusumFoldNeg mu0 k s xs := by
  induction xs generalizing s with
  | nil =>
    simp [cusumFoldPos, cusumFoldNeg, hs]
  | cons x rest ih =>
    have hpos : 0 ≤ cusumStepPos s x mu0 k := by
      unfold cusumStepPos
      split <;> omega
    have hneg : 0 ≤ cusumStepNeg s x mu0 k := by
      unfold cusumStepNeg
      split <;> omega
    exact ⟨(ih (cusumStepPos s x mu0 k) hpos).1, (ih (cusumStepNeg s x mu0 k) hneg).2⟩

def InDeadband (mu0 k : Int) : List Int → Prop
  | [] => True
  | x :: xs => (mu0 - k ≤ x ∧ x ≤ mu0 + k) ∧ InDeadband mu0 k xs

theorem T09_cusum_deadband_exact_zero (mu0 k : Int) (xs : List Int) (hdb : InDeadband mu0 k xs) :
    cusumFoldPos mu0 k 0 xs = 0 ∧ cusumFoldNeg mu0 k 0 xs = 0 := by
  induction xs with
  | nil =>
    simp [cusumFoldPos, cusumFoldNeg]
  | cons x rest ih =>
    rcases hdb with ⟨hx, hrest⟩
    have hstepP : cusumStepPos 0 x mu0 k = 0 := by
      unfold cusumStepPos
      split <;> omega
    have hstepN : cusumStepNeg 0 x mu0 k = 0 := by
      unfold cusumStepNeg
      split <;> omega
    simp [cusumFoldPos, cusumFoldNeg, hstepP, hstepN, ih hrest]

theorem T10_cusum_state_monotone_in_initial_score
    (mu0 k : Int) (xs : List Int) (s1 s2 : Int) (hle : s1 ≤ s2) :
    cusumFoldPos mu0 k s1 xs ≤ cusumFoldPos mu0 k s2 xs := by
  induction xs generalizing s1 s2 with
  | nil =>
    simpa [cusumFoldPos] using hle
  | cons x rest ih =>
    simp only [cusumFoldPos]
    apply ih
    unfold cusumStepPos
    split <;> split <;> omega

theorem T11_cusum_threshold_alarm_antitone
    (h1 h2 score : Int) (hle : h1 ≤ h2) (halarm : cusumAlarmAt h2 score = true) :
    cusumAlarmAt h1 score = true := by
  unfold cusumAlarmAt at halarm ⊢
  simp [decide_eq_true_eq] at halarm ⊢
  omega

def SustainedShiftPos (mu0 k d : Int) : List Int → Prop
  | [] => True
  | x :: xs => (mu0 + k + d ≤ x) ∧ SustainedShiftPos mu0 k d xs

theorem T12_cusum_sustained_shift_linear_growth (mu0 k d : Int) (hd : 1 ≤ d)
    (xs : List Int) (s : Int) (hs : 0 ≤ s) (hshift : SustainedShiftPos mu0 k d xs) :
    s + (xs.length : Int) * d ≤ cusumFoldPos mu0 k s xs := by
  induction xs generalizing s with
  | nil =>
    simp [cusumFoldPos]
  | cons x rest ih =>
    rcases hshift with ⟨hx, hrest⟩
    have hstep : s + d ≤ cusumStepPos s x mu0 k := by
      unfold cusumStepPos
      split <;> omega
    have hstep_nonneg : 0 ≤ cusumStepPos s x mu0 k := Int.le_trans (by omega) hstep
    have hrec := ih (cusumStepPos s x mu0 k) hstep_nonneg hrest
    simp only [cusumFoldPos, List.length_cons]
    rw [Int.natCast_add, Int.natCast_one, Int.add_mul, Int.one_mul]
    have hlhs : s + ((rest.length : Int) * d + d) = (s + d) + (rest.length : Int) * d := by
      rw [← Int.add_assoc, Int.add_right_comm s ((rest.length : Int) * d) d]
    rw [hlhs]
    exact Int.le_trans (Int.add_le_add_right hstep ((rest.length : Int) * d)) hrec

def corroboratedInfraAlarm (consecutive429 corroborationWindow : Nat) : Bool :=
  decide (corroborationWindow ≤ consecutive429)

theorem T13_corroboration_window_blocks_transient_429_burst
    (burst window persist : Nat) (hburst : burst < window) (hpersist : window ≤ persist) :
    corroboratedInfraAlarm burst window = false ∧
    corroboratedInfraAlarm persist window = true := by
  unfold corroboratedInfraAlarm
  refine ⟨?_, ?_⟩
  · simp [decide_eq_false_iff_not]
    omega
  · simp [decide_eq_true_eq]
    omega

-- ============================================================================
-- 3. Ville (1939) Discrete Non-Negative Supermartingale Stopping Bound
-- ============================================================================

inductive StoppedETree : Type where
  | terminal : Nat → Nat → StoppedETree
  | stopped : Nat → Nat → StoppedETree
  | branch : Nat → StoppedETree → StoppedETree → StoppedETree

def rootWealth : StoppedETree → Nat
  | .terminal _ w => w
  | .stopped _ w => w
  | .branch w _ _ => w

def probMass : StoppedETree → Nat
  | .terminal m _ => m
  | .stopped m _ => m
  | .branch _ l r => probMass l + probMass r

def alarmMass (M : Nat) : StoppedETree → Nat
  | .terminal m w => if M ≤ w then m else 0
  | .stopped m _ => m
  | .branch _ l r => alarmMass M l + alarmMass M r

def expectedStoppedWealth : StoppedETree → Nat
  | .terminal m w => m * w
  | .stopped m w => m * w
  | .branch _ l r => expectedStoppedWealth l + expectedStoppedWealth r

def ValidSupermartingale (M : Nat) : StoppedETree → Prop
  | .terminal _ _ => True
  | .stopped _ w => M ≤ w
  | .branch w l r =>
      probMass l * rootWealth l + probMass r * rootWealth r ≤ (probMass l + probMass r) * w ∧
      ValidSupermartingale M l ∧
      ValidSupermartingale M r

theorem T14_doob_optional_stopping_tree (M : Nat) (t : StoppedETree)
    (hvalid : ValidSupermartingale M t) :
    expectedStoppedWealth t ≤ probMass t * rootWealth t := by
  induction t with
  | terminal m w =>
    simp [expectedStoppedWealth, probMass, rootWealth]
  | stopped m w =>
    simp [expectedStoppedWealth, probMass, rootWealth]
  | branch w l r ihl ihr =>
    rcases hvalid with ⟨hstep, hvl, hvr⟩
    have hl := ihl hvl
    have hr := ihr hvr
    simp only [expectedStoppedWealth, probMass, rootWealth]
    omega

theorem T15_markov_stopped_wealth_domination (M : Nat) (t : StoppedETree)
    (hvalid : ValidSupermartingale M t) :
    M * alarmMass M t ≤ expectedStoppedWealth t := by
  induction t with
  | terminal m w =>
    simp only [alarmMass, expectedStoppedWealth]
    split
    · next hmw =>
      have hmul : M * m ≤ w * m := Nat.mul_le_mul_right m hmw
      have hcomm : w * m = m * w := Nat.mul_comm w m
      omega
    · simp
  | stopped m w =>
    simp only [ValidSupermartingale] at hvalid
    simp only [alarmMass, expectedStoppedWealth]
    have hmul : M * m ≤ w * m := Nat.mul_le_mul_right m hvalid
    have hcomm : w * m = m * w := Nat.mul_comm w m
    omega
  | branch w l r ihl ihr =>
    rcases hvalid with ⟨_, hvl, hvr⟩
    have hl := ihl hvl
    have hr := ihr hvr
    simp only [alarmMass, expectedStoppedWealth, Nat.mul_add]
    omega

theorem T16_ville_one_sided_anytime_false_alarm_bound (M : Nat) (t : StoppedETree)
    (hvalid : ValidSupermartingale M t) :
    M * alarmMass M t ≤ probMass t * rootWealth t := by
  have h1 := T15_markov_stopped_wealth_domination M t hvalid
  have h2 := T14_doob_optional_stopping_tree M t hvalid
  omega

theorem T17_ville_two_sided_union_false_alarm_bound
    (M P W0 alarmUnion : Nat) (tPos tNeg : StoppedETree)
    (hvPos : ValidSupermartingale M tPos) (hvNeg : ValidSupermartingale M tNeg)
    (hpPos : probMass tPos = P) (hpNeg : probMass tNeg = P)
    (hwPos : rootWealth tPos = W0) (hwNeg : rootWealth tNeg = W0)
    (hunion : alarmUnion ≤ alarmMass M tPos + alarmMass M tNeg) :
    M * alarmUnion ≤ 2 * (P * W0) := by
  have hbPos := T16_ville_one_sided_anytime_false_alarm_bound M tPos hvPos
  have hbNeg := T16_ville_one_sided_anytime_false_alarm_bound M tNeg hvNeg
  rw [hpPos, hwPos] at hbPos
  rw [hpNeg, hwNeg] at hbNeg
  have hmul : M * alarmUnion ≤ M * (alarmMass M tPos + alarmMass M tNeg) :=
    Nat.mul_le_mul_left M hunion
  rw [Nat.mul_add] at hmul
  omega

-- ============================================================================
-- 4. RFC 6962 Certificate Transparency Domain Separation Non-Collision
-- ============================================================================

def rfc6962LeafInput (leafBytes : List UInt8) : List UInt8 :=
  (0 : UInt8) :: leafBytes

def rfc6962NodeInput (leftHash rightHash : List UInt8) : List UInt8 :=
  (1 : UInt8) :: (leftHash ++ rightHash)

structure TaggedHashAlg where
  compress : UInt8 → Nat → Nat → Nat

def TaggedHashAlg.Injective (alg : TaggedHashAlg) : Prop :=
  ∀ t1 a1 b1 t2 a2 b2,
    alg.compress t1 a1 b1 = alg.compress t2 a2 b2 → t1 = t2 ∧ a1 = a2 ∧ b1 = b2

theorem T18_rfc6962_leaf_node_domain_disjoint
    (alg : TaggedHashAlg) (hinj : alg.Injective)
    (leafBytes leftHash rightHash : List UInt8) (leafDigest lNode rNode : Nat) :
    rfc6962LeafInput leafBytes ≠ rfc6962NodeInput leftHash rightHash ∧
    alg.compress 0x00 leafDigest 0 ≠ alg.compress 0x01 lNode rNode := by
  refine ⟨?_, ?_⟩
  · unfold rfc6962LeafInput rfc6962NodeInput
    intro h
    injection h with hhead _
    exact absurd hhead (by decide)
  · intro hcol
    have htags := (hinj 0x00 leafDigest 0 0x01 lNode rNode hcol).1
    exact absurd htags (by decide)

#print axioms T01_bezout_coprime_167_288
#print axioms T02_general_coprime_weyl_injective
#print axioms T03_weyl_slot_288_collision_free
#print axioms T04_weyl_offset_1440_collision_free
#print axioms T05_weyl_offset_in_day_and_5min_aligned
#print axioms T06_driftbench50_hourly_minimax_dispersion
#print axioms T07_http304_egress_strictly_bounded_and_saved
#print axioms T08_cusum_nonneg_invariant
#print axioms T09_cusum_deadband_exact_zero
#print axioms T10_cusum_state_monotone_in_initial_score
#print axioms T11_cusum_threshold_alarm_antitone
#print axioms T12_cusum_sustained_shift_linear_growth
#print axioms T13_corroboration_window_blocks_transient_429_burst
#print axioms T14_doob_optional_stopping_tree
#print axioms T15_markov_stopped_wealth_domination
#print axioms T16_ville_one_sided_anytime_false_alarm_bound
#print axioms T17_ville_two_sided_union_false_alarm_bound
#print axioms T18_rfc6962_leaf_node_domain_disjoint

end DriftWatch.Formal
