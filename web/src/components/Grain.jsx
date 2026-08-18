export function Grain() {
  return (
    <div
      aria-hidden="true"
      className="pointer-events-none fixed inset-0 opacity-[0.09] mix-blend-overlay"
      style={{
        backgroundImage:
          "url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='160' height='160'><filter id='n'><feTurbulence type='fractalNoise' baseFrequency='0.8' numOctaves='4' stitchTiles='stitch'/></filter><rect width='100%' height='100%' filter='url(%23n)' opacity='0.55'/></svg>\")",
      }}
    />
  );
}
