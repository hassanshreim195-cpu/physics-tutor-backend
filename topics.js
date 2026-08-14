// Canonical curriculum topics per grade, mirrored from GRADE_CONTENT in study-plan.html.
// This is the server-side source of truth used to seed the `topics` table and to
// validate/resolve the topic strings the AI returns from /api/generate-exam.
//
// IMPORTANT: if GRADE_CONTENT in study-plan.html changes (a lesson renamed/added/removed),
// mirror the change here too, or topic lookups for that grade will silently fall back to
// "Uncategorized". Long-term this list should probably be authored once and shared by both
// the frontend and backend instead of kept in sync by hand — flagged for later.

const CURRICULUM = {
  g7: [
    "Solids and Liquids",
    "Volume",
    "Mass and Density",
    "Gaseous State",
    "Constitution of Matter",
    "Transfer of Heat",
    "Electric Circuit",
    "Electric Measurements",
    "Effects of Electric Current",
  ],
  g8: [
    "Motion",
    "Velocity",
    "Mechanical Actions",
    "Forces",
    "Weight",
    "Friction",
    "Rectilinear Propagation of Light",
    "Reflection of Light",
    "Mechanical Waves",
    "Electromagnetic Waves",
  ],
  g9: [
    "Pressure in Liquids",
    "Archimedes' Principle",
    "DC Voltage (Tension continue)",
    "Resistors (Conducteurs ohmiques)",
    "Electric Power and Energy",
    "Mechanical Actions",
    "Hooke's Law (Springs)",
    "Equilibrium of a Body",
    "Alternating Voltage",
    "The Voltage of the Mains",
  ],
  g10: [
    "Description of Motion",
    "Rectilinear Motion",
    "Force and Interaction",
    "Propagation of Light",
    "Reflection of Light",
    "Refraction of Light",
    "Electrostatics",
    "Potential Difference",
    "Electric Current",
    "Resistors",
    "Generators and Receivers",
  ],
  g11lit: [
    "Electric Current",
    "Transformers and Power Transmission",
    "Domestic Electricity and its Dangers",
    "Sources and Aspects of Light",
    "Electromagnetic Waves",
    "Vibratory Nature of Sound",
    "The Human Ear as a Sound Detector",
  ],
  bacse: [
    "Work and Mechanical Energy",
    "Forms of Energy",
    "Sources of Energy and the Pollution they Cause",
    "Radioactivity",
    "Stimulated Nuclear Reactions: Fission and Fusion",
    "Applications and Dangers of Radioactivity",
  ],
  g11sci: [
    "Waves",
    "Emission and Propagation of Sound",
    "Reception of Sound",
    "Acoustic Energy",
    "Motion of a Particle in a Plane",
    "Uniform Circular Motion",
    "Newton's 2nd Law and its Applications",
    "Systems of Particles",
    "Work and Energy",
    "Mechanical Power",
    "Capacitors",
    "Magnetic Field Created by an Electric Current",
    "Electromagnetic Force",
    "Rotational Dynamics",
  ],
  bacls: [
    "Energy",
    "Linear Momentum",
    "Simple Harmonic Motion (Pendulum)",
    "Alternating Sinusoidal Current",
    "RC Circuit (Capacitor Charge and Discharge)",
    "Wave Aspect of Light — Diffraction",
    "Corpuscular Aspect of Light — Photoelectric Effect",
    "The Atom",
    "Atomic Nucleus",
    "Radioactivity",
  ],
  bacgs: [
    "Energy",
    "Linear Momentum",
    "Simple Harmonic Motion (Pendulum)",
    "Electromagnetic Induction",
    "Self-induction",
    "Alternating Sinusoidal Current",
    "RC Circuit (Capacitor Charge and Discharge)",
    "LC Oscillator (Free Electrical Oscillations)",
    "Wave Aspect of Light — Diffraction",
    "Corpuscular Aspect of Light — Photoelectric Effect",
    "The Atom",
    "Atomic Nucleus",
    "Radioactivity",
    "Nuclear Reactions",
  ],
};

// Mistake taxonomy — first draft (see the design doc, section 9, for the human-readable
// version and notes). Keyed by topic TITLE, not by grade+title, so repeated topic names
// (e.g. "Radioactivity" across bacse/bacls/bacgs) currently share one tag set. Split this
// into `${grade}::${title}` keys later if a topic ever needs different tags per grade.
// Every entry ends with "other" so the grader always has a fallback bucket.
const MISTAKE_TAXONOMY = {
  "Solids and Liquids": ["confuses-solid-liquid-properties", "incompressibility-confusion", "other"],
  "Volume": ["wrong-volume-unit", "displacement-method-error", "formula-misuse", "other"],
  "Mass and Density": ["density-formula-inversion", "mass-density-confusion", "unit-mismatch", "other"],
  "Gaseous State": ["gas-compressibility-confusion", "particle-spacing-misconception", "other"],
  "Constitution of Matter": ["continuous-matter-misconception", "particle-motion-misconception", "other"],
  "Transfer of Heat": ["mode-confusion", "heat-temperature-confusion", "other"],
  "Electric Circuit": ["current-consumption-misconception", "series-parallel-confusion", "open-circuit-misread", "other"],
  "Electric Measurements": ["meter-placement-error", "reading-scale-error", "other"],
  "Effects of Electric Current": ["effect-type-confusion: mixes up thermal/magnetic/chemical effects", "cause-effect-confusion", "other"],

  "Motion": ["reference-frame-confusion", "rest-vs-motion-misconception", "other"],
  "Velocity": ["speed-velocity-confusion", "formula-misuse", "unit-conversion-error", "other"],
  "Mechanical Actions": ["contact-noncontact-confusion", "action-effect-confusion", "missing-force", "other"],
  "Forces": ["force-direction-error", "missing-force", "vector-representation-error", "other"],
  "Friction": ["friction-direction-error: thinks friction acts in the direction of motion instead of opposing it", "other"],
  "Hooke's Law (Springs)": ["hookes-law-formula-misuse: wrong variables in F=kx or PE=½kx²", "unit-conversion-error: cm vs m not converted before computing", "restoring-force-direction-error: forgets the restoring force opposes displacement", "other"],
  "Weight": ["weight-mass-confusion", "g-value-error", "other"],
  "Rectilinear Propagation of Light": ["shadow-formation-error", "propagation-misconception", "other"],
  "Reflection of Light": ["angle-measurement-error", "law-of-reflection-misapplied", "image-position-error", "other"],
  "Mechanical Waves": ["wave-property-confusion", "medium-misconception", "other"],
  "Electromagnetic Waves": ["medium-misconception", "spectrum-order-error", "other"],

  "Pressure in Liquids": ["formula-misuse", "depth-confusion", "unit-error", "other"],
  "Archimedes' Principle": ["buoyant-force-formula-misuse: wrong variables in F=ρVg", "own-density-confusion: thinks the buoyant force depends on the object's own density/weight instead of the displaced liquid", "float-sink-reasoning-error", "other"],
  "DC Voltage (Tension continue)": ["voltage-current-confusion", "meter-placement-error", "other"],
  "Resistors (Conducteurs ohmiques)": ["ohms-law-inversion", "series-parallel-resistance-error", "unit-error", "other"],
  "Electric Power and Energy": ["formula-confusion", "unit-error", "other"],
  "Equilibrium of a Body": ["force-balance-error", "missing-force", "direction-sign-error", "other"],
  "Alternating Voltage": ["ac-dc-confusion", "period-frequency-confusion", "other"],
  "The Voltage of the Mains": ["peak-rms-confusion", "safety-misconception", "other"],

  "Description of Motion": ["reference-frame-confusion", "trajectory-position-confusion", "other"],
  "Rectilinear Motion": ["graph-misreading", "uniform-accelerated-confusion", "formula-misuse", "other"],
  "Force and Interaction": ["action-reaction-confusion", "missing-force", "other"],
  "Propagation of Light": ["shadow-formation-error", "propagation-misconception", "other"],
  "Refraction of Light": ["snells-law-misapplied", "direction-of-bending-error", "other"],
  "Electrostatics": ["charge-conservation-error", "coulombs-law-misuse", "induction-vs-conduction-confusion", "other"],
  "Potential Difference": ["voltage-current-confusion", "meter-placement-error", "other"],
  "Electric Current": ["current-direction-confusion", "meter-placement-error", "other"],
  "Resistors": ["series-parallel-resistance-error", "ohms-law-inversion", "other"],
  "Generators and Receivers": ["energy-conversion-confusion", "emf-voltage-confusion", "other"],

  "Transformers and Power Transmission": ["turns-ratio-inversion", "step-up-down-confusion", "other"],
  "Domestic Electricity and its Dangers": ["safety-misconception", "series-parallel-confusion", "other"],
  "Sources and Aspects of Light": ["source-property-confusion", "other"],
  "Vibratory Nature of Sound": ["medium-misconception", "vibration-source-confusion", "other"],
  "The Human Ear as a Sound Detector": ["anatomy-function-confusion", "frequency-range-error", "other"],

  "Work and Mechanical Energy": ["formula-misuse", "work-energy-confusion", "other"],
  "Forms of Energy": ["conversion-confusion", "conservation-violation", "other"],
  "Sources of Energy and the Pollution they Cause": ["renewable-nonrenewable-confusion", "pollution-source-confusion", "other"],
  "Radioactivity": ["decay-type-confusion", "half-life-misuse", "other"],
  "Stimulated Nuclear Reactions: Fission and Fusion": ["fission-fusion-confusion", "mass-energy-error", "other"],
  "Applications and Dangers of Radioactivity": ["safety-misconception", "application-mismatch", "other"],

  "Waves": ["wave-property-confusion", "transverse-longitudinal-confusion", "other"],
  "Emission and Propagation of Sound": ["medium-speed-confusion", "medium-misconception", "other"],
  "Reception of Sound": ["intensity-loudness-confusion", "other"],
  "Acoustic Energy": ["db-scale-misconception", "formula-misuse", "other"],
  "Motion of a Particle in a Plane": ["vector-component-error", "projectile-symmetry-error", "other"],
  "Uniform Circular Motion": ["centripetal-force-as-extra-force: treats centripetal force as an additional force instead of naming which real force provides it", "constant-speed-zero-force-misconception: thinks constant speed means zero net force", "formula-misuse", "other"],
  "Newton's 2nd Law and its Applications": ["missing-force-in-fbd", "wrong-force-direction", "mass-weight-confusion", "sign-error", "other"],
  "Systems of Particles": ["internal-external-force-confusion", "center-of-mass-error", "other"],
  "Work and Energy": ["work-energy-confusion", "formula-misuse", "other"],
  "Mechanical Power": ["power-work-confusion: mixes up total work with the rate of doing work", "formula-misuse", "other"],
  "Capacitors": ["qcv-formula-misuse", "series-parallel-capacitance-error", "other"],
  "Magnetic Field Created by an Electric Current": ["right-hand-rule-error", "field-magnitude-formula-error", "other"],
  "Electromagnetic Force": ["force-direction-error", "formula-misuse", "other"],
  "Rotational Dynamics": ["torque-formula-misuse", "linear-rotational-confusion", "other"],

  "Energy": ["conversion-confusion", "conservation-violation", "other"],
  "Linear Momentum": ["momentum-formula-misuse", "conservation-violation", "other"],
  "Simple Harmonic Motion (Pendulum)": ["period-formula-misuse: wrong variables in T=2π√(L/g)", "amplitude-period-confusion: thinks amplitude changes the period (it doesn't, for small angles)", "length-unit-error: cm vs m not converted before computing", "other"],
  "Alternating Sinusoidal Current": ["peak-rms-confusion", "period-frequency-confusion", "other"],
  "RC Circuit (Capacitor Charge and Discharge)": ["time-constant-formula-misuse: wrong variables in τ=RC", "instant-voltage-change-misconception: thinks capacitor voltage jumps instantly", "charge-discharge-formula-confusion: mixes up the charging and discharging exponential forms", "other"],
  "LC Oscillator (Free Electrical Oscillations)": ["period-formula-misuse: wrong variables in T=2π√(LC)", "energy-conservation-error: doesn't track the capacitor/inductor energy exchange correctly", "amplitude-period-confusion", "other"],
  "Wave Aspect of Light — Diffraction": ["diffraction-condition-error", "wave-particle-confusion", "other"],
  "Corpuscular Aspect of Light — Photoelectric Effect": ["threshold-frequency-error", "photon-energy-formula-misuse", "other"],
  "The Atom": ["energy-level-confusion", "structure-misconception", "other"],
  "Atomic Nucleus": ["mass-atomic-number-confusion", "nucleon-count-error", "other"],

  "Electromagnetic Induction": ["lenz-law-direction-error", "flux-change-misconception", "other"],
  "Self-induction": ["inductance-formula-misuse", "back-emf-misconception", "other"],
  "Nuclear Reactions": ["fission-fusion-confusion", "mass-energy-error", "other"],
};

function topicsForGrade(grade) {
  return CURRICULUM[grade] || [];
}

function tagsForTopic(title) {
  return MISTAKE_TAXONOMY[title] || ["other"];
}

module.exports = { CURRICULUM, MISTAKE_TAXONOMY, topicsForGrade, tagsForTopic };
