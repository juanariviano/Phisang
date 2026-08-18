import { useRef } from "react";
import { motion, useMotionValue, useSpring } from "framer-motion";

export function MagneticButton({ children, className = "", disabled, ...props }) {
  const ref = useRef(null);
  const x = useMotionValue(0);
  const y = useMotionValue(0);
  const springX = useSpring(x, { stiffness: 160, damping: 18, mass: 0.4 });
  const springY = useSpring(y, { stiffness: 160, damping: 18, mass: 0.4 });

  function onMove(event) {
    const node = ref.current;
    if (!node || disabled) return;
    const rect = node.getBoundingClientRect();
    x.set((event.clientX - (rect.left + rect.width / 2)) * 0.18);
    y.set((event.clientY - (rect.top + rect.height / 2)) * 0.18);
  }

  function onLeave() {
    x.set(0);
    y.set(0);
  }

  return (
    <motion.button
      ref={ref}
      type="submit"
      disabled={disabled}
      style={{ x: springX, y: springY }}
      whileTap={{ scaleX: 1.04, scaleY: 0.9 }}
      transition={{ type: "spring", stiffness: 520, damping: 18 }}
      onMouseMove={onMove}
      onMouseLeave={onLeave}
      className={`relative isolate cursor-pointer rounded-full bg-ink px-8 py-3.5 font-display text-sm font-extrabold uppercase tracking-[0.1em] text-peel transition-colors hover:bg-forest disabled:cursor-not-allowed disabled:bg-leaf/40 disabled:text-paper ${className}`}
      {...props}
    >
      <span className="relative">{children}</span>
    </motion.button>
  );
}
