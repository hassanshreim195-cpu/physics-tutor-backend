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
// Grades 7-10 genuinely use a mix of True/False (always "correct the false statement", never
// just mark it), some multiple-choice, and problems. Grade 11 almost never uses multiple-choice
// in real papers. Grade 12 (all three tracks — GS/LS/SE) NEVER uses True/False or multiple-
// choice in real exams — every real Grade 12 paper we found is 100% multi-part structured
// problems. Forcing MCQ/TF onto Grade 11-12 content (which the generator used to do uniformly
// for every grade) is a big part of why generated questions felt "off" — it's not what a real
// Lebanese exam at that level looks like.
const GRADE_STYLE_GUIDE = {
  g7: {
    label: 'Grade 7',
    scope: 'Solids & Liquids -> Volume -> Mass & Density (incl. relative density, unit conversion) -> Gaseous State -> Constitution of Matter / Heat Transfer (conduction, convection, radiation) -> Electric Circuits (conductors vs insulators, open vs closed) -> Electric Measurements.',
    types: ['tf', 'mcq', 'problem'],
    conventions: 'True/False items always require correcting the false statement, never just marking it. Multiple-choice uses lettered a/b/c options and is common in physics at this grade. Calculation problems use a concrete named object (a metal prism, a rock) with given dimensions/mass, building step by step: find volume -> find density -> convert units -> find relative density (density relative to water, given explicitly as rho_water = 1 g/cm3). Units are strict SI/metric with heavy emphasis on conversion literacy (g<->kg<->ton, mL<->L<->dm3<->cm3). Electric-circuit questions are simple single-step concept questions (conductor vs insulator, open vs closed circuit) with no calculation.',
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
    conventions: 'This is a national government exam year, so phrasing is formal and exam-board-style. True/False always requires correcting the false statement. Real bubble-style multiple-choice essentially never appears in Brevet physics papers — favor True/False and scaffolded problems only. Problems are heavily scaffolded: each sub-answer feeds the next (find the equivalent resistance -> deduce the current -> deduce a voltage -> deduce another current), and almost every sub-question demands justification ("Justify", "Deduce with justification", "Show that") rather than a bare number. g is always given explicitly as g=10 N/kg. Numeric values are deliberately non-round (e.g. R=45.2 ohm) to force real calculation rather than pattern matching.',
    example: 'True/False: "The image formed by a converging lens is always real." (correct it if false). Problem: "A dry cell of EMF E=9V and internal resistance r=0.5 ohm feeds a circuit of two resistors R1=15 ohm and R2=25 ohm in series. 1) Calculate the equivalent resistance. 2) Deduce the current I in the circuit. 3) Calculate the voltage across R1. Justify each step."',
  },
  g10: {
    label: 'Grade 10',
    scope: 'Electrostatics (Coulomb\'s law) -> Potential Difference -> Electric Current -> Resistors -> Generators & Receivers / Motors (back-emf) -> Refraction of Light (critical angle, total internal reflection) -> Description of Motion / Rectilinear Motion (ticker-tape / dot-print timers) -> Mechanical Equilibrium/Statics -> Mechanical Waves (transverse waves, water waves, speed change between deep and shallow water).',
    types: ['tf', 'mcq', 'problem'],
    conventions: 'Exercises are scenario-driven with a named character performing an experiment (e.g. "Karim builds an electric circuit...") rather than a bare abstract setup, walking through it via scaffolded sub-questions. Strong, repeated command-verb vocabulary: "Determine", "Deduce", "Calculate", "Justify your answer", "Show that", "Specify", "Indicate", "Construct with justification". True/False always requires correcting the false statement. Diagrams/figures are referenced constantly, and many questions assume the student reads values off a figure/graph. g is given explicitly (g=10 N/kg or 10 m/s^2). Point values are shown per sub-question.',
    example: 'True/False: "Two resistors connected in parallel have an equivalent resistance greater than either resistor alone." (correct it if false). Problem: "Karim shines a light ray from water into air at an angle of incidence of 35 degrees. Given the critical angle for water-air is 49 degrees: 1) Determine whether total internal reflection occurs. 2) Construct, with justification, the path of the refracted or reflected ray."',
  },
  g11lit: {
    label: 'Grade 11 — Literary/Humanities',
    scope: 'Direct/alternating current via oscilloscope (vertical sensitivity, waveform reading) -> dry cell energy conversions & simple power/efficiency -> transformers (turns ratio, step-up/down, efficiency) -> mechanical energy conservation (simple 1D cases only, no rotation, no vectors) -> basic radioactive decay -> applied/environmental physics questions built around a short reading passage (e.g. water pollution).',
    types: ['problem'],
    conventions: 'Markedly lighter than the Scientific track: simple, single-formula plug-and-solve steps, direct definition/identification sub-questions ("Give one difference between...", "State the law of..."), no vectors, no rotational dynamics, no calculus-heavy motion. Occasionally built around a short reading passage with mostly qualitative, light-on-computation sub-questions. g is always given explicitly. No True/False or multiple-choice appears in real papers at this level — write scaffolded, moderately-light multi-part problems only.',
    example: 'Problem: "A dry cell has EMF E=6V and internal resistance r=0.5 ohm and delivers a current of 1.5A for 20 minutes. 1) Calculate the potential difference U across its terminals. 2) Calculate the total power delivered. 3) Deduce the total electrical energy delivered during this time."',
  },
  g11sci: {
    label: 'Grade 11 — Scientific',
    scope: 'Kinematics of plane motion (position/velocity/acceleration vectors, tangential & normal acceleration, circular motion) -> Newton\'s Second Law (inclined planes, pulleys, friction) -> Rotational Dynamics (moment of inertia, torque, equilibrium of rigid bodies) -> Work & Mechanical Energy (springs, friction losses) -> Capacitors & RC circuits (time constant) -> Electric & Magnetic Fields -> Waves (sound, interference, standing waves, Doppler effect) -> introductory nuclear physics (radioactive decay).',
    types: ['tf', 'problem'],
    conventions: 'Vector- and calculus-heavy relative to the other tracks: position/velocity/acceleration vectors, moment of inertia, multi-step derivations. Frequently frames a problem as a real-world story (a basketball shot, a block on an incline) to make an otherwise abstract vector/calculus problem concrete. True/False always requires correcting the false statement, but real MCQ essentially never appears at this level. Strong command-verb vocabulary ("Deduce", "Justify", "Determine", "Show that", "Prove that"). "Given:" blocks list numeric data explicitly with SI units; g is given explicitly.',
    example: 'True/False: "In uniform circular motion, the tangential acceleration is zero but the normal acceleration is not." Problem: "A block of mass 2 kg is released from rest at the top of a frictionless incline of angle 30 degrees and length 4 m. 1) Determine the acceleration of the block along the incline. 2) Deduce its speed at the bottom. 3) Show that this result matches the value obtained using the work-energy theorem."',
  },
  bacse: {
    label: 'Grade 12 — Sociology-Economics / Literature (SE)',
    scope: 'Only 3-4 units, much lighter than the science tracks: Energy (work/mechanical energy framed around real-world topics such as vehicles, renewable energy, pollution) -> Radioactivity & Nuclear Reactions (basic decay law, half-life, fission/fusion energy, medical/biological effects) -> The Universe (solar system, history of astronomy). This track explicitly EXCLUDES RLC circuits, oscillations, electromagnetic induction, rotational mechanics, and the photoelectric effect/atomic energy levels.',
    types: ['problem'],
    conventions: 'Real Grade 12 exams in every track (SE/LS/GS) never use True/False or multiple-choice — every real paper found is 100% multi-part structured problems, broken into small numbered sub-parts worth fractional points summing to 20. SE is the lightest and shortest of the three Grade-12 tracks, commonly built around a real-world or historical reading passage with mostly qualitative/definitional sub-questions and only light arithmetic. Verbs: "Calculate", "Determine", "Deduce", "Explain", "Name". Constants are always given explicitly.',
    example: 'Problem: "Read the following short passage about the discovery of radioactivity... 1) Name the phenomenon described. 2) A sample of a radioactive isotope has a half-life of 8 days and an initial mass of 40 g. Calculate the mass remaining after 24 days. 3) Explain, in your own words, one practical application of radioactivity."',
  },
  bacls: {
    label: 'Grade 12 — Life Sciences (LS)',
    scope: 'Mechanical Energy (conservation/non-conservation on inclined planes, solved both by an "energetic method" and an "analytical/Newton\'s-law method") -> Linear Momentum / Collisions (elastic & inelastic) -> Mechanical Oscillations (elastic pendulum only — no torsion/compound pendulum, that is GS-only) -> Electromagnetic Induction & Capacitor Charge/Discharge (RC) -> Alternating Sinusoidal Current (RLC series) -> Diffraction & Interference of Light -> Photoelectric Effect -> The Atom / Radioactivity / Nuclear Reactions (fission/fusion).',
    types: ['problem'],
    conventions: 'Same as the other Grade-12 tracks: no True/False or multiple-choice, only scaffolded multi-part problems. A distinctive LS convention: problems are often solved BOTH by an "energetic method" and an "analytical/Newton\'s law" method for the same scenario. Many sub-questions ask the student to "Verify that [a given expression] is a solution" or "Show that [a stated result holds]" rather than open-ended solving — the target result is given, and the student must derive it, which is a different phrasing style from just "calculate X". Constants (g, h, c, e) are always given explicitly.',
    example: 'Problem: "A block of mass 200 g is attached to a horizontal spring of stiffness k=50 N/m and released from rest after being displaced 5 cm from equilibrium (assume no friction). 1) Energetic method: show that the maximum speed of the block is v_max = Xm*omega0 where omega0 = sqrt(k/m), and calculate its value. 2) Analytical method: write Newton\'s second law for the block and verify that x(t) = Xm*cos(omega0*t) is a solution of the resulting differential equation."',
  },
  bacgs: {
    label: 'Grade 12 — General Sciences (GS)',
    scope: 'Everything in the Life Sciences track plus the heaviest content: Rotation & Moment of Inertia (compound/torsion pendulums — GS-only) -> Newton\'s 2nd Law verification & Collisions/Linear Momentum -> Mechanical Oscillations (elastic, compound, torsion pendulum) -> Capacitor charge/discharge (RC), Self-Induction, RLC series AC circuits, Transformers, Electromagnetic Oscillations -> Diffraction & Interference of Light, Photoelectric Effect -> Atom/Nucleus (hydrogen energy levels, radioactivity, nuclear fission/fusion).',
    types: ['problem'],
    conventions: 'The heaviest and most calculation-dense of the three Grade-12 tracks — includes rotational mechanics (moment of inertia, torsion pendulum) that LS and SE don\'t cover. Same convention as LS/SE: no True/False or multiple-choice, multi-part scaffolded problems with "Show that" / "Verify that" / "Deduce" sub-questions guiding toward a stated result. Constants always given explicitly with SI units.',
    example: 'Problem: "A uniform disk of mass 2 kg and radius 0.3 m rotates about its central axis under a constant torque of 1.5 N.m, starting from rest. Given the moment of inertia of a disk I = (1/2)mR^2: 1) Calculate I. 2) Determine the angular acceleration. 3) Deduce the angular velocity after 4 seconds."',
  },
};

module.exports = { GRADE_STYLE_GUIDE };
