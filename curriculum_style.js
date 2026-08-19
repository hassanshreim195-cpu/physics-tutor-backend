// Real Lebanese physics exam style grounding, per grade.
//
// Where this came from: Hasan (the site owner) pointed us at his Google Drive, which holds a
// large personal collection of real Lebanese physics exams/tests/worksheets and official
// Ministry-style "Annual Distribution" (syllabus/pacing) documents spanning grades 7-12,
// gathered from many different schools over the years. We read a representative sample per
// grade to find out what actually gets asked in Lebanon at each level — topic scope/order,
// which question TYPES are actually used (this varies a lot by grade — see below), and the
// concrete phrasing/format conventions real exams use.
//
// IMPORTANT: the `example` string per grade below is NOT copied from any real file. It's
// something we wrote ourselves, in the *pattern* we observed (same command verbs, same
// given-value conventions, same structure), specifically so the AI prompts below never embed
// verbatim third-party exam content — those real files belong to the schools/teachers who
// wrote them. `scope` and `conventions` are factual summaries of format/coverage, not quotes.
//
// Big cross-grade finding worth calling out: question TYPE MIX is NOT uniform across grades.
// Grades 7-9 genuinely use a mix of True/False (always "correct the false statement", never
// just mark it), some multiple-choice, and problems. From Grade 10 upward, real papers lean
// almost entirely on multi-part structured problems with decimal sub-numbering (2.1/2.2, a.1/
// a.2) — MCQ essentially never appears from Grade 10 on, and True/False becomes rare (an
// occasional opening concept-check, not a pillar of the exam). Grade 11 almost never uses
// multiple-choice in real papers. Grade 12 (all three tracks — GS/LS/SE) NEVER uses True/False
// or multiple-choice in real exams — every real Grade 12 paper we found is 100% multi-part
// structured problems. Forcing MCQ/TF onto Grade 10-12 content (which the generator used to do
// uniformly for every grade) is a big part of why generated questions felt "off" — it's not
// what a real Lebanese exam at that level looks like.
//
// Notation findings from a second, deeper Drive pass worth encoding everywhere they apply:
// - Voltage/potential difference is written U (not V) from Grade 9 upward — French-influenced
//   convention ("tension"), e.g. U_AB, U_PN. Ohm's law is U = R*I, not V = IR.
// - Pressure is P = F/S (S = surface/area), not P = F/A.
// - "rho" is reused for BOTH density (Grade 7+) and resistivity (Grade 9+, R = rho*L/S) —
//   disambiguate by chapter/context rather than assuming one meaning.
// - Frequency is always f (or occasionally F), never N — N is reserved for number of nuclei
//   (radioactive decay, N = N0*e^(-lambda*t)), transformer turns (N1/N2, though n1/n2 also
//   appears), or nucleon/mass number (A). Period is T.
// - Generators/motors: source EMF is E with internal resistance r (uppercase E); a motor's
//   back-emf is e with internal resistance r' (lowercase e) — the case distinguishes source
//   from receiver, worth preserving in generated problems that involve both.
// - Radioactivity: decay constant lambda, half-life T, activity A (Bq) — consistent everywhere.
// - Capacitors: C = q/U (charge over voltage), consistent everywhere.
const GRADE_STYLE_GUIDE = {
  g7: {
    label: 'Grade 7',
    scope: 'Solids & Liquids -> Volume -> Mass & Density (incl. relative density, unit conversion) -> Gaseous State -> Constitution of Matter / Heat Transfer (conduction, convection, radiation) -> Electric Circuits (conductors vs insulators, open vs closed) -> Electric Measurements.',
    types: ['tf', 'mcq', 'problem'],
    conventions: 'True/False items always require correcting the false statement, never just marking it. Multiple-choice uses lettered a/b/c options and is common in physics at this grade. Calculation problems use a concrete named object (a metal prism, a rock, a found coin/metal piece identified via a density lookup table of aluminum/copper/iron/gold/silver/bronze/lead) with given dimensions/mass, building step by step: find volume -> find density (rho = m/V, use rho not "d") -> convert units -> find relative density (R.D., density relative to water, given explicitly as rho_water = 1 g/cm3). g/cm3 is the grade-7-native working unit for density; converting g/cm3 <-> kg/m3 is itself a tested skill, not just one fixed system. Units are strict SI/metric with heavy emphasis on conversion literacy (g<->kg<->ton, mL<->L<->dm3<->cm3). Electric-circuit questions are simple single-step concept questions (conductor vs insulator, open vs closed circuit) with no calculation. Marks are sometimes shown as fractional points (e.g. "5 1/2 pts").',
    example: 'True/False style: "A liquid takes the shape of its container but keeps a fixed volume." (state true or false, and correct it if false). Problem style: "A rectangular block has length 8 cm, width 5 cm, height 4 cm and a mass of 320 g. Calculate its volume, then its density in g/cm3, then convert this density to kg/m3."',
  },
  g8: {
    label: 'Grade 8',
    scope: 'Description of Motion (trajectory, relativity of motion) -> Speed (average/instantaneous, uniform vs accelerated, km/h<->m/s) -> Forces / Mechanical Actions (contact vs distance forces, weight W=mg with g=10N/kg given explicitly, tension, friction, force diagrams drawn to a stated scale) -> Work & Forms of Mechanical Energy -> Waves & Oscillations (period T, frequency f=1/T, pendulum, sound as a longitudinal wave, audible range 20 Hz-20,000 Hz) -> Electromagnetic Spectrum (ordering by frequency/wavelength: radio, visible light, UV, X-rays).',
    types: ['tf', 'problem'],
    conventions: 'Exams are organized as several titled "Exercises" each worth stated points, almost always opening with a True/False "correct the false statement(s)" block of short physics claims. Physics at this grade leans on True/False and short scaffolded calculation problems over multiple-choice (MCQ shows up more in this teacher\'s chemistry tests than physics). Force diagrams must be drawn to a stated scale (e.g. "scale: 1 cm -> 4 N"). g is always given explicitly as g=10 N/kg. Scenarios use concrete, locally-grounded settings and Lebanese names.',
    example: 'True/False: "The weight of a body is the same on the Earth and on the Moon because its mass does not change." (correct it if false). Problem: "An astronaut carries an oxygen tank of mass 12 kg. Given g_Earth=10 N/kg and g_Moon=1.6 N/kg: 1) Calculate the weight of the tank on Earth. 2) Calculate its weight on the Moon. 3) Is it easier to carry on Earth or on the Moon? Justify."',
  },
  g9: {
    label: 'Grade 9 (Brevet)',
    scope: 'Refraction of Light & Converging Lenses (image construction) -> DC Voltage & Circuits -> Resistors (series/parallel) -> Electric Power & Energy (including real-world cost) -> Alternating Voltage / Voltage of the Mains -> Mechanical Actions/Forces -> Equilibrium of a Body (Hooke\'s law) -> Pressure in Liquids. This is the official Brevet (national certificate exam) year.',
    types: ['tf', 'problem'],
    conventions: 'This is a national government exam year, so phrasing is formal and exam-board-style. True/False always requires correcting the false statement. Real bubble-style multiple-choice essentially never appears in Brevet physics papers — favor True/False and scaffolded problems only. Problems are heavily scaffolded, often with decimal sub-numbering (1.1, 1.2, 1.3): each sub-answer feeds the next (find the equivalent resistance -> deduce the current -> deduce a voltage -> deduce another current), and almost every sub-question demands justification ("Justify", "Deduce with justification", "Show that") rather than a bare number. Voltage is written U (not V), and Ohm\'s law is U = R*I; resistors in a circuit narrative are sometimes labeled as components (D), (D\') rather than R1/R2. g is always given explicitly as g=10 N/kg. Pressure (in the "Pressure in Liquids" unit) is P = F/S. Numeric values are deliberately non-round (e.g. R=45.2 ohm) to force real calculation rather than pattern matching. Strong local-context framing: car battery diagnostics, home electric outlets, "cost in LL (Lebanese Lira)" for kWh usage.',
    example: 'True/False: "The image formed by a converging lens is always real." (correct it if false). Problem: "A dry cell of EMF E=9V and internal resistance r=0.5 ohm feeds a circuit of two resistors R1=15 ohm and R2=25 ohm in series. 1) Calculate the equivalent resistance. 2) Deduce the current I in the circuit. 3) Calculate the voltage U across R1. Justify each step."',
  },
  g10: {
    label: 'Grade 10',
    scope: 'Electrostatics (Coulomb\'s law) -> Potential Difference -> Electric Current -> Resistors -> Generators & Receivers / Motors (back-emf) -> Refraction of Light (critical angle, total internal reflection) -> Description of Motion / Rectilinear Motion (ticker-tape / dot-print timers) -> Mechanical Equilibrium/Statics -> Mechanical Waves (transverse waves, water waves, speed change between deep and shallow water).',
    types: ['tf', 'problem'],
    conventions: 'From this grade upward, real exams lean heavily on multi-part structured problems with decimal sub-numbering (2.1/2.2, 5.1/5.2/5.3) — essentially the same structure as Grades 11-12, not a set of standalone questions. Multiple-choice essentially never appears; True/False survives only as an occasional short opening concept-check, not a main pillar. Exercises are scenario-driven with a named character performing an experiment (e.g. "Karim builds an electric circuit...") rather than a bare abstract setup, walking through it via scaffolded sub-questions. Strong, repeated command-verb vocabulary: "Determine", "Deduce", "Calculate", "Justify your answer", "Show that", "Specify", "Indicate", "Construct with justification", "Apply the law of addition of voltages", "Apply the junction rule". Voltage is written U (not V); resistivity is R = rho*L/S; a generator carries EMF E and internal resistance r, while a motor/receiver carries back-emf e and internal resistance r\' (the lowercase marks it as a receiver, not a source). True/False always requires correcting the false statement when it does appear. Diagrams/figures are referenced constantly, and many questions assume the student reads values off a figure/graph. g is given explicitly (g=10 N/kg or 10 m/s^2). Point values are shown per sub-question.',
    example: 'True/False (occasional opener only): "Two resistors connected in parallel have an equivalent resistance greater than either resistor alone." (correct it if false). Problem: "Karim shines a light ray from water into air at an angle of incidence of 35 degrees. Given the critical angle for water-air is 49 degrees: 2.1) Determine whether total internal reflection occurs. 2.2) Construct, with justification, the path of the refracted or reflected ray."',
  },
  g11lit: {
    label: 'Grade 11 — Literary/Humanities',
    scope: 'Direct/alternating current via oscilloscope (vertical sensitivity, waveform reading) -> dry cell energy conversions & simple power/efficiency -> transformers (turns ratio, step-up/down, efficiency) -> mechanical energy conservation (simple 1D cases only, no rotation, no vectors) -> basic radioactive decay -> applied/environmental physics questions built around a short reading passage (e.g. water pollution).',
    types: ['problem'],
    conventions: 'Markedly lighter than the Scientific track: simple, single-formula plug-and-solve steps, direct definition/identification sub-questions ("Give one difference between...", "State the law of..."), no vectors, no rotational dynamics, no calculus-heavy motion. A "read carefully the following text" reading-comprehension exercise (a science-and-society topic, light or no math) is a real, recurring convention across the Literary track at this grade, not just at Grade 12 SE. Transformer turns are written as n1/n2 in some papers and N1/N2 (uppercase) in others — both conventions coexist, either is fine. g is always given explicitly. No True/False or multiple-choice appears in real papers at this level — write scaffolded, moderately-light multi-part problems only.',
    example: 'Problem: "A dry cell has EMF E=6V and internal resistance r=0.5 ohm and delivers a current of 1.5A for 20 minutes. 1) Calculate the potential difference U across its terminals. 2) Calculate the total power delivered. 3) Deduce the total electrical energy delivered during this time."',
  },
  g11sci: {
    label: 'Grade 11 — Scientific',
    scope: 'Kinematics of plane motion (position/velocity/acceleration vectors, tangential & normal acceleration, circular motion) -> Newton\'s Second Law (inclined planes, pulleys, friction) -> Rotational Dynamics (moment of inertia, torque, equilibrium of rigid bodies) -> Work & Mechanical Energy (springs, friction losses) -> Capacitors & RC circuits (time constant) -> Electric & Magnetic Fields -> Waves (sound, interference, standing waves, Doppler effect) -> introductory nuclear physics (radioactive decay).',
    types: ['tf', 'problem'],
    conventions: 'Vector- and calculus-heavy relative to the other tracks: position/velocity/acceleration vectors, moment of inertia, multi-step derivations. Frequently frames a problem as a real-world story (a basketball shot, a block on an incline) to make an otherwise abstract vector/calculus problem concrete. True/False always requires correcting the false statement, but real MCQ essentially never appears at this level. Strong command-verb vocabulary ("Deduce", "Justify", "Determine", "Show that", "Prove that"). "Given:" blocks list numeric data explicitly with SI units; g is given explicitly. Capacitor voltage is written u_C (lowercase, instantaneous) and charge as q; frequency is f (never N), period T.',
    example: 'True/False: "In uniform circular motion, the tangential acceleration is zero but the normal acceleration is not." Problem: "A block of mass 2 kg is released from rest at the top of a frictionless incline of angle 30 degrees and length 4 m. 1) Determine the acceleration of the block along the incline. 2) Deduce its speed at the bottom. 3) Show that this result matches the value obtained using the work-energy theorem."',
  },
  bacse: {
    label: 'Grade 12 — Sociology-Economics / Literature (SE)',
    scope: 'Only 3-4 units, much lighter than the science tracks: Energy (work/mechanical energy framed around real-world topics such as vehicles, renewable energy, pollution) -> Radioactivity & Nuclear Reactions (basic decay law, half-life, fission/fusion energy, medical/biological effects) -> The Universe (solar system, history of astronomy). This track explicitly EXCLUDES RLC circuits, oscillations, electromagnetic induction, rotational mechanics, and the photoelectric effect/atomic energy levels.',
    types: ['problem'],
    conventions: 'Real Grade 12 exams in every track (SE/LS/GS) never use True/False or multiple-choice — every real paper found is 100% multi-part structured problems, broken into small numbered sub-parts worth fractional points summing to 20. Confirmed format: 1 hour, 3 exercises, 20 points total (e.g. 6+8+6). SE is officially paired with the Literature/Humanities (LH) track under Lebanon\'s CERD curriculum — they share the same physics paper and teacher\'s guide, so "SE" and "Literature/Humanities Grade 12" content are effectively the same physics. It is the lightest and shortest of the Grade-12 tracks, and reliably includes one exercise built as a "read carefully the following text" reading passage (e.g. solar system, pollution, car/fuel economics) paired with mostly qualitative/definitional sub-questions and only light arithmetic. Verbs: "Calculate", "Determine", "Deduce", "Explain", "Name". Constants are always given explicitly.',
    example: 'Problem: "Read the following short passage about the discovery of radioactivity... 1) Name the phenomenon described. 2) A sample of a radioactive isotope has a half-life of 8 days and an initial mass of 40 g. Calculate the mass remaining after 24 days. 3) Explain, in your own words, one practical application of radioactivity."',
  },
  bacls: {
    label: 'Grade 12 — Life Sciences (LS)',
    scope: 'Mechanical Energy (conservation/non-conservation on inclined planes, solved both by an "energetic method" and an "analytical/Newton\'s-law method") -> Linear Momentum / Collisions (elastic & inelastic) -> Mechanical Oscillations (elastic pendulum only — no torsion/compound pendulum, that is GS-only) -> Electromagnetic Induction & Capacitor Charge/Discharge (RC) -> Alternating Sinusoidal Current (RLC series) -> Diffraction & Interference of Light -> Photoelectric Effect -> The Atom / Radioactivity / Nuclear Reactions (fission/fusion).',
    types: ['problem'],
    conventions: 'Same as the other Grade-12 tracks: no True/False or multiple-choice, only scaffolded multi-part problems. A distinctive, confirmed-real LS convention: problems are often explicitly headered in two labeled sub-parts for the SAME scenario — e.g. "1. Energetic method" then "2. Analytical Study" — where the energetic part uses mechanical-energy conservation to find a speed, and the analytical part applies Newton\'s second law / the work-energy theorem to the same setup (found verbatim-structured this way in a real 2025 trial exam, e.g. for a two-mass pulley system). Many sub-questions ask the student to "Verify that [a given expression] is a solution" or "Show that [a stated result holds]" rather than open-ended solving — the target result is given, and the student must derive it, which is a different phrasing style from just "calculate X". KE, PE (or GPE), and ME are used as explicit multi-letter abbreviations directly in the problem text, not just inside formulas. Constants (g, h, c, e) are always given explicitly.',
    example: 'Problem: "A block of mass 200 g is attached to a horizontal spring of stiffness k=50 N/m and released from rest after being displaced 5 cm from equilibrium (assume no friction). 1) Energetic method: show that the maximum speed of the block is v_max = Xm*omega0 where omega0 = sqrt(k/m), and calculate its value. 2) Analytical method: write Newton\'s second law for the block and verify that x(t) = Xm*cos(omega0*t) is a solution of the resulting differential equation."',
  },
  bacgs: {
    label: 'Grade 12 — General Sciences (GS)',
    scope: 'Everything in the Life Sciences track plus the heaviest content: Rotation & Moment of Inertia (compound/torsion pendulums — GS-only) -> Newton\'s 2nd Law verification & Collisions/Linear Momentum -> Mechanical Oscillations (elastic, compound, torsion pendulum) -> Capacitor charge/discharge (RC), Self-Induction, RLC series AC circuits, Transformers, Electromagnetic Oscillations -> Diffraction & Interference of Light, Photoelectric Effect -> Atom/Nucleus (hydrogen energy levels, radioactivity, nuclear fission/fusion).',
    types: ['problem'],
    conventions: 'The heaviest and most calculation-dense of the three Grade-12 tracks — includes rotational mechanics (moment of inertia, torsion pendulum) that LS and SE don\'t cover. Confirmed real format: 4 obligatory exercises per official BAC session, spanning mechanics/momentum, oscillations, AC/RC/RL circuits, light (interference/photoelectric/energy levels), and nuclear physics. Same convention as LS/SE: no True/False or multiple-choice, multi-part scaffolded problems with "Show that" / "Verify that" / "Deduce" sub-questions guiding toward a stated result. Newton\'s second law is frequently written in momentum form, sum(F) = dP/dt, reflecting this track\'s linear-momentum chapter — accept this as equally valid phrasing alongside F = ma. Constants always given explicitly with SI units.',
    example: 'Problem: "A uniform disk of mass 2 kg and radius 0.3 m rotates about its central axis under a constant torque of 1.5 N.m, starting from rest. Given the moment of inertia of a disk I = (1/2)mR^2: 1) Calculate I. 2) Determine the angular acceleration. 3) Deduce the angular velocity after 4 seconds."',
  },
};

module.exports = { GRADE_STYLE_GUIDE };
