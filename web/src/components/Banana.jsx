import { useId } from "react";

// A shared curved silhouette keeps every verdict recognizable at icon size.
const BODY = "M54 43 C43 79 55 123 89 146 C129 173 180 144 193 97 C172 121 146 133 117 120 C86 106 70 78 67 44 Z";
const PALETTES = {
  benign: { light: "#FFE985", mid: "#F8C83C", dark: "#DDA423", edge: "#96701E", stem: "#617C3D" },
  checking: { light: "#F2EF99", mid: "#D5D767", dark: "#A7B74F", edge: "#70813B", stem: "#526D35" },
  phishing: { light: "#F6D879", mid: "#DEB64F", dark: "#BB8D34", edge: "#896329", stem: "#736238", bruises: true },
  rotten: { light: "#D5BC77", mid: "#B69650", dark: "#876434", edge: "#655030", stem: "#645435", bruises: true, rotten: true },
  unavailable: { light: "#DFE2D2", mid: "#BDC4AC", dark: "#A0AB8E", edge: "#788368", stem: "#788368" },
};

function Fly({ x, y, index }) {
  return <g transform={`translate(${x} ${y})`} aria-hidden="true">
    <g className="banana-fly" style={{ animationDelay: `${index * -2.1}s`, animationDuration: `${4.8 + index}s` }}>
      <g className="banana-fly-wings" fill="#E2E7D9" stroke="#65715C" strokeWidth="0.8">
        <ellipse cx="-4" cy="-2.5" rx="4.5" ry="2.6" transform="rotate(28 -4 -2.5)" />
        <ellipse cx="4" cy="-2.5" rx="4.5" ry="2.6" transform="rotate(-28 4 -2.5)" />
      </g>
      <ellipse rx="2.5" ry="3.7" fill="#3D4032" />
      <circle cy="-3.8" r="2" fill="#303629" />
    </g>
  </g>;
}

export function Banana({ state = "benign", width, height, frame = "full", className = "" }) {
  const cfg = PALETTES[state === "malware" ? "rotten" : state] || PALETTES.unavailable;
  const id = useId();
  const gradient = `banana-fill-${id}`;
  const clip = `banana-clip-${id}`;
  const compact = frame === "tight";
  const box = compact ? { viewBox: "35 18 166 140", width: 166, height: 140 } : { viewBox: "0 0 220 180", width: 220, height: 180 };
  const w = width ?? (height ? height * box.width / box.height : 132);
  const h = height ?? w * box.height / box.width;
  const checking = state === "checking";

  return <svg viewBox={box.viewBox} width={w} height={h} className={className} role="img"
    aria-label={cfg.rotten ? "High risk: rotten banana" : `${state}: banana`}>
    <defs>
      <linearGradient id={gradient} x1="70" y1="59" x2="114" y2="158" gradientUnits="userSpaceOnUse">
        <stop stopColor={cfg.light} />
        <stop offset="0.6" stopColor={cfg.mid} />
        <stop offset="1" stopColor={cfg.dark} />
      </linearGradient>
      <clipPath id={clip}><path d={BODY} /></clipPath>
    </defs>

    {!compact && <ellipse className={checking ? "banana-scan-shadow" : undefined}
      cx="120" cy="164" rx="51" ry="5" fill="#435331" opacity="0.1" />}

    <g className={checking ? "banana-scan-fruit" : cfg.rotten ? "banana-rot-fruit" : undefined}>
      <path d="M55 49 49 29 Q48 25 52 24 L62 22 Q66 22 67 27 L69 48Z"
        fill={cfg.stem} stroke={cfg.edge} strokeWidth="2.5" strokeLinejoin="round" />
      <path d="m54 29 7-2" stroke="#F0E7B5" strokeWidth="2.5" strokeLinecap="round" opacity="0.55" />
      <path d={BODY} fill={`url(#${gradient})`} stroke={cfg.edge} strokeWidth="2.5" strokeLinejoin="round" />
      <g clipPath={`url(#${clip})`}>
        <path d="M50 65 C58 111 85 144 124 147 C153 151 180 125 193 97 L203 165 65 171Z"
          fill={cfg.dark} opacity="0.28" />
        <path d="M61 58 C61 95 81 121 106 133" fill="none" stroke={cfg.light}
          strokeWidth="7" strokeLinecap="round" opacity="0.8" />
        <path d="M68 57 C72 102 102 139 140 140" fill="none" stroke={cfg.edge}
          strokeWidth="1.8" strokeLinecap="round" opacity="0.3" />
        {cfg.bruises && <g fill={cfg.rotten ? "#674B2C" : "#A17B37"} opacity={cfg.rotten ? "0.82" : "0.65"}>
          <path d="M81 115 C75 111 72 118 77 126 C80 133 92 139 97 134 C102 129 91 118 87 119Z" />
          <path d="M145 135 C140 130 130 134 132 141 C132 149 145 150 151 144 C155 139 152 137 145 135Z" />
          {cfg.rotten && <>
            <path d="M55 77 C49 79 53 98 60 101 C69 104 71 95 66 87 C62 82 63 76 55 77Z" />
            <path d="M169 123 C163 124 160 134 165 135 C173 136 181 123 178 119 C175 115 172 122 169 123Z" />
            <circle cx="115" cy="149" r="2.1" /><circle cx="104" cy="140" r="1.5" />
            <circle cx="72" cy="112" r="1.7" />
          </>}
        </g>}
      </g>
      <path d="M185 104 Q190 98 194 95 Q196 94 197 98 L194 105 189 109Z"
        fill={cfg.rotten ? "#493C28" : "#80602B"} stroke={cfg.edge} strokeWidth="1.3" strokeLinejoin="round" />
    </g>

    {checking && <g className="banana-scan-sparks" stroke="#819440" strokeWidth="2" strokeLinecap="round" aria-hidden="true">
      <path d="M151 45v10m-5-5h10" /><circle cx="34" cy="112" r="2" fill="#BAC660" stroke="none" />
    </g>}
    {cfg.rotten && !compact && <><Fly x={35} y={71} index={0} /><Fly x={169} y={54} index={1} /></>}
  </svg>;
}
