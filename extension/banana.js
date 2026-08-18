/**
 * The verdict, as a banana. Mirrors web/src/components/Banana.jsx.
 *
 * Sealed means there was nothing to open: benign is untouched, and "unread"
 * means the check failed before anything could be opened. Peeled means Phisang
 * found something — and how far the peel swings is severity, so malware opens
 * wider than phishing.
 *
 * The hinge is CSS (see .peel-flap in theme.css), which pins the rotation
 * origin to the stem in viewBox units. Rotating each strip about its own centre
 * instead scissors them across each other.
 */
(function () {
  const PEEL_LEFT =
    "M80 34 C 66 44 56 84 56 120 C 56 152 66 174 80 184 C 75 150 71 100 76 40 Z";
  const PEEL_CENTER =
    "M76 40 C 71 100 75 150 80 184 C 85 186 89 184 91 178 C 87 148 87 96 84 40 Z";
  const PEEL_RIGHT =
    "M84 40 C 87 96 87 148 91 178 C 101 168 104 146 104 120 C 104 84 94 44 80 34 Z";
  const FLESH =
    "M80 42 C 71 58 68 92 68 120 C 68 148 73 170 82 178 C 91 170 96 148 96 120 C 96 92 90 58 80 42 Z";

  const LEFT_SPOTS = [[62, 74, 3], [60, 104, 2.4], [60, 134, 3.4], [66, 160, 2.4]];
  const CENTER_SPOTS = [[80, 64, 2.4], [84, 110, 3], [82, 150, 2.6]];
  const RIGHT_SPOTS = [[100, 70, 2.6], [99, 102, 3.2], [100, 132, 2.8], [96, 158, 3.2]];
  const FLESH_SPOTS = [[78, 72, 4], [88, 104, 5.5], [74, 132, 4.5], [86, 158, 3.5]];

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
      fleshSpotOpacity: 0.5,
    },
    malware: {
      open: 40,
      peel: "#FFBF00",
      stem: "#467235",
      tip: "#0E1408",
      flesh: "#C0A87A",
      fleshSpots: "#1C1508",
      fleshSpotOpacity: 0.8,
    },
  };

  let instance = 0;

  function spots(points, fill, opacity) {
    if (!fill) return "";
    return points
      .map(
        (p) =>
          '<circle cx="' + p[0] + '" cy="' + p[1] + '" r="' + p[2] + '" fill="' + fill +
          '" opacity="' + (opacity || 0.85) + '"/>'
      )
      .join("");
  }

  function strip(cls, d, pts, cfg, hatchId) {
    return (
      '<g class="peel-flap ' + cls + '">' +
      '<path d="' + d + '" fill="' + cfg.peel + '"/>' +
      (cfg.hatch ? '<path d="' + d + '" fill="url(#' + hatchId + ')"/>' : "") +
      spots(pts, cfg.peelSpots) +
      (cls === "flap-c"
        ? '<ellipse cx="86" cy="183" rx="4.4" ry="5.6" fill="' + cfg.tip + '"/>'
        : "") +
      "</g>"
    );
  }

  /** Renders the banana into `container` and lets CSS transition it open. */
  function renderBanana(container, state, width) {
    if (!container) return;
    const cfg = STATES[state] || STATES.unavailable;
    const w = width || 116;
    const open = cfg.open > 0;
    const hatchId = "ph-hatch-" + ++instance;

    const fruit = cfg.flesh
      ? '<g class="peel-fruit"><path d="' + FLESH + '" fill="' + cfg.flesh + '"/>' +
        spots(FLESH_SPOTS, cfg.fleshSpots, cfg.fleshSpotOpacity) +
        "</g>"
      : "";

    const left = strip("flap-l", PEEL_LEFT, LEFT_SPOTS, cfg, hatchId);
    const center = strip("flap-c", PEEL_CENTER, CENTER_SPOTS, cfg, hatchId);
    const right = strip("flap-r", PEEL_RIGHT, RIGHT_SPOTS, cfg, hatchId);

    // Order is the depth cue we have in 2D: sealed, the centre strip covers the
    // fruit; opened, it falls behind it.
    const body = open ? center + fruit + left + right : fruit + left + center + right;

    container.innerHTML =
      '<svg class="banana' + (cfg.pulse ? " banana-pulse" : "") + '" viewBox="-30 0 220 200"' +
      ' width="' + w + '" height="' + Math.round((w * 200) / 220) + '"' +
      ' style="--peel-open:' + cfg.open + 'deg"' +
      ' role="img" aria-label="' + state + ": peel " + (open ? "opened" : "intact") + '">' +
      '<defs><pattern id="' + hatchId + '" width="8" height="8" patternTransform="rotate(45)"' +
      ' patternUnits="userSpaceOnUse">' +
      '<line x1="0" y1="0" x2="0" y2="8" stroke="#467235" stroke-width="1.6" opacity="0.45"/>' +
      "</pattern></defs>" +
      '<path d="M80 38 C 78 27 76 20 74 12" fill="none" stroke="' + cfg.stem +
      '" stroke-width="9" stroke-linecap="round"/>' +
      body +
      "</svg>";

    // Paint sealed for a frame, then flip the class so the peel transitions.
    const svg = container.firstChild;
    requestAnimationFrame(function () {
      requestAnimationFrame(function () {
        if (open) svg.classList.add("is-open");
      });
    });
  }

  self.Phisang = Object.assign(self.Phisang || {}, { renderBanana });
})();
