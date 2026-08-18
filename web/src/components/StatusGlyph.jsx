import {
  CircleNotch,
  Eye,
  EyeSlash,
  SealWarning,
  ShieldWarning,
} from "@phosphor-icons/react";

const MAP = {
  malware: ShieldWarning,
  phishing: SealWarning,
  benign: Eye,
  unavailable: EyeSlash,
  checking: CircleNotch,
};

export function StatusGlyph({ kind, size = 28, weight = "bold" }) {
  const Icon = MAP[kind] || EyeSlash;
  return <Icon size={size} weight={weight} className={kind === "checking" ? "animate-spin" : ""} />;
}
