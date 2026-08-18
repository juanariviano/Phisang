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
    const dx = event.clientX - (rect.left + rect.width / 2);
    const dy = event.clientY - (rect.top + rect.height / 2);
    x.set(dx * 0.22);
    y.set(dy * 0.22);
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
      whileTap={{ scale: 0.98 }}
      onMouseMove={onMove}
      onMouseLeave={onLeave}
      className={`relative isolate overflow-hidden rounded-full bg-accent px-6 py-3.5 text-sm font-semibold tracking-tight text-paper transition-opacity disabled:opacity-40 ${className}`}
      {...props}
    >
      <span className="relative">{children}</span>
    </motion.button>
  );
}
