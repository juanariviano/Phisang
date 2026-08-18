import {
  CircleDashed,
  CircleNotch,
  MinusCircle,
  ShieldWarning,
  Warning,
} from "@phosphor-icons/react";

const MAP = {
  malware: ShieldWarning,
  phishing: Warning,
  benign: CircleDashed,
  unavailable: MinusCircle,
  checking: CircleNotch,
};

export function StatusGlyph({ kind, size = 28 }) {
  const Icon = MAP[kind] || MinusCircle;
  const spin = kind === "checking" ? "animate-spin" : "";
  return <Icon size={size} weight="regular" className={spin} />;
}
