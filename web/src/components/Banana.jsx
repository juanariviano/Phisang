import { useEffect, useId, useState } from "react";

/**
 * The verdict, as a banana.
 *
 * Sealed means there was nothing to open: benign is untouched, and "unread"
 * means the check failed before anything could be opened. Peeled means Phisang
 * found something and is showing it — and how far the peel swings is severity,
 * so malware opens wider than phishing.
 *
 * Geometry lives in a 160x200 space. Three peel strips tile the closed fruit
 * and all hinge on the stem at 80,36. The "full" frame leaves room either side
 * for the peel to swing into; "tight" crops to the sealed fruit and is what the
 * brand mark uses, since a logo never opens.
 *
 * The hinge is plain CSS rather than a motion library on purpose: motion
 * libraries default SVG children to `transform-box: fill-box` with a centre
 * origin, which rotates each strip about itself and scissors them across each
 * other. `.peel-flap` pins the origin to the stem in viewBox units.
 *
 * Rotation signs: SVG's positive angle is clockwise, so a point below the hinge
 * swings LEFT — the left strip takes a positive angle, the right a negative one.
 */
const PEEL_LEFT =
  "M80 34 C 66 44 56 84 56 120 C 56 152 66 174 80 184 C 75 150 71 100 76 40 Z";
const PEEL_CENTER =
  "M76 40 C 71 100 75 150 80 184 C 85 186 89 184 91 178 C 87 148 87 96 84 40 Z";
const PEEL_RIGHT =
  "M84 40 C 87 96 87 148 91 178 C 101 168 104 146 104 120 C 104 84 94 44 80 34 Z";
const FLESH =
  "M80 42 C 71 58 68 92 68 120 C 68 148 73 170 82 178 C 91 170 96 148 96 120 C 96 92 90 58 80 42 Z";

const LEFT_SPOTS = [
  [62, 74, 3],
  [60, 104, 2.4],
  [60, 134, 3.4],
  [66, 160, 2.4],
];
const CENTER_SPOTS = [
  [80, 64, 2.4],
  [84, 110, 3],
  [82, 150, 2.6],
];
const RIGHT_SPOTS = [
  [100, 70, 2.6],
  [99, 102, 3.2],
  [100, 132, 2.8],
  [96, 158, 3.2],
];
const FLESH_SPOTS = [
  [78, 72, 4],
  [88, 104, 5.5],
  [74, 132, 4.5],
  [86, 158, 3.5],
];

const FRAMES = {
  full: { viewBox: "-30 0 220 200", w: 220, h: 200 },
  tight: { viewBox: "48 2 64 192", w: 64, h: 192 },
};

const STATES = {
  benign: { open: 0, peel: "#FFBF00", stem: "#467235", tip: "#8A5A0F" },
  checking: { open: 0, peel: "#8FBF5C", stem: "#467235", tip: "#467235", pulse: true },
  unavailable: { open: 0, peel: "#C2C7B4", stem: "#467235", tip: "#5C6B4F", hatch: true },
  phishing: {
    open: 26,
    peel: "#E0A526",
    stem: "#8A5A0F",
    tip: "#5B3A08",
    peelSpots: "#8A5A0F",
    flesh: "#EBD9A0",
    fleshSpots: "#8A5A0F",
  },
  malware: {
    open: 40,
    peel: "#FFBF00",
    stem: "#467235",
    tip: "#0E1408",
    flesh: "#C0A87A",
    fleshSpots: "#1C1508",
    rotHeavy: true,
  },
};

function Spots({ points, fill, opacity = 0.85 }) {
  if (!fill) return null;
  return points.map(([cx, cy, r]) => (
    <circle key={`${cx}-${cy}`} cx={cx} cy={cy} r={r} fill={fill} opacity={opacity} />
  ));
}

export function Banana({ state = "benign", width, height, frame = "full", className = "" }) {
  const cfg = STATES[state] || STATES.unavailable;
  const box = FRAMES[frame] || FRAMES.full;
  // Pattern ids must be unique or a second banana on the page resolves its
  // fill against the first one's def.
  const hatchId = `ph-hatch-${useId()}`;
  const w = width ?? (height ? (height * box.w) / box.h : 132);
  const h = height ?? (w * box.h) / box.w;
  const open = cfg.open > 0;

  // Render sealed for one frame, then let CSS transition the peel open.
  const [engaged, setEngaged] = useState(false);
  useEffect(() => {
    setEngaged(false);
    const id = requestAnimationFrame(() => requestAnimationFrame(() => setEngaged(true)));
    return () => cancelAnimationFrame(id);
  }, [state]);

  const angle = engaged ? cfg.open : 0;
  const flap = (degrees) => ({
    className: "peel-flap",
    style: { transform: `rotate(${degrees}deg)` },
  });

  const Left = (
    <g key="left" {...flap(angle)}>
      <path d={PEEL_LEFT} fill={cfg.peel} />
      {cfg.hatch && <path d={PEEL_LEFT} fill={`url(#${hatchId})`} />}
      <Spots points={LEFT_SPOTS} fill={cfg.peelSpots} />
    </g>
  );

  const Right = (
    <g key="right" {...flap(-angle)}>
      <path d={PEEL_RIGHT} fill={cfg.peel} />
      {cfg.hatch && <path d={PEEL_RIGHT} fill={`url(#${hatchId})`} />}
      <Spots points={RIGHT_SPOTS} fill={cfg.peelSpots} />
    </g>
  );

  const Center = (
    <g key="center" {...flap(open && engaged ? 5 : 0)}>
      <path d={PEEL_CENTER} fill={cfg.peel} />
      {cfg.hatch && <path d={PEEL_CENTER} fill={`url(#${hatchId})`} />}
      <Spots points={CENTER_SPOTS} fill={cfg.peelSpots} />
      {/* Blossom tip: the small dark nub that says "banana" louder than the
          silhouette does. It rides the centre strip. */}
      <ellipse cx="86" cy="183" rx="4.4" ry="5.6" fill={cfg.tip} />
    </g>
  );

  const Fruit = cfg.flesh ? (
    <g key="flesh" className="peel-fruit" style={{ opacity: engaged ? 1 : 0 }}>
      <path d={FLESH} fill={cfg.flesh} />
      <Spots points={FLESH_SPOTS} fill={cfg.fleshSpots} opacity={cfg.rotHeavy ? 0.8 : 0.5} />
    </g>
  ) : null;

  return (
    <svg
      viewBox={box.viewBox}
      width={w}
      height={h}
      className={`${cfg.pulse ? "banana-pulse" : ""} ${className}`}
      role="img"
      aria-label={`${state}: peel ${open ? "opened" : "intact"}`}
    >
      <defs>
        <pattern
          id={hatchId}
          width="8"
          height="8"
          patternTransform="rotate(45)"
          patternUnits="userSpaceOnUse"
        >
          <line x1="0" y1="0" x2="0" y2="8" stroke="#467235" strokeWidth="1.6" opacity="0.45" />
        </pattern>
      </defs>

      {/* Stem stays put while the peel swings away from it. */}
      <path
        d="M80 38 C 78 27 76 20 74 12"
        fill="none"
        stroke={cfg.stem}
        strokeWidth="9"
        strokeLinecap="round"
      />

      {/* Order is the depth cue we have in 2D: sealed, the centre strip covers
          the fruit; opened, it falls behind it. */}
      {open ? [Center, Fruit, Left, Right] : [Fruit, Left, Center, Right]}
    </svg>
  );
}
