import { useEffect } from "react";
import { motion } from "framer-motion";
import { BifrostLogo } from "./BifrostLogo";

export function Splash({ onDone }: { onDone: () => void }) {
  useEffect(() => {
    const t = setTimeout(onDone, 3600);
    return () => clearTimeout(t);
  }, [onDone]);

  const word = "BIFROST".split("");

  return (
    <div className="fixed inset-0 z-50 bg-[#050505] flex flex-col items-center justify-center overflow-hidden">
      {/* the bridge forming */}
      <svg className="absolute w-[140%] h-72 opacity-70" viewBox="0 0 1000 200" preserveAspectRatio="none">
        <defs>
          <linearGradient id="splashbridge" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor="#7B2FBE" />
            <stop offset="25%" stopColor="#9D4EDD" />
            <stop offset="50%" stopColor="#E040FB" />
            <stop offset="75%" stopColor="#E91E8C" />
            <stop offset="100%" stopColor="#F48FB1" />
          </linearGradient>
        </defs>
        <motion.path
          d="M -50 180 Q 500 -40 1050 180"
          stroke="url(#splashbridge)"
          strokeWidth="6"
          fill="none"
          strokeLinecap="round"
          initial={{ pathLength: 0, opacity: 0 }}
          animate={{ pathLength: 1, opacity: 1 }}
          transition={{ duration: 1.8, ease: "easeInOut" }}
          style={{ filter: "drop-shadow(0 0 18px rgba(224,64,251,0.7))" }}
        />
        <motion.path
          d="M 0 180 Q 500 10 1000 180"
          stroke="url(#splashbridge)"
          strokeWidth="2"
          fill="none"
          opacity={0.5}
          initial={{ pathLength: 0 }}
          animate={{ pathLength: 1 }}
          transition={{ duration: 2.2, ease: "easeInOut" }}
        />
      </svg>

      <motion.div
        initial={{ opacity: 0, scale: 0.7 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ delay: 1, duration: 1, type: "spring" }}
        className="relative z-10"
      >
        <BifrostLogo className="w-24 h-24" />
      </motion.div>

      <div className="relative z-10 mt-6 flex">
        {word.map((c, i) => (
          <motion.span
            key={i}
            initial={{ opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 1.6 + i * 0.12, duration: 0.4 }}
            className="text-5xl font-extrabold tracking-[0.2em] rainbow-text"
          >
            {c}
          </motion.span>
        ))}
      </div>

      <motion.p
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 2.8, duration: 0.8 }}
        className="relative z-10 mt-5 text-sm text-muted-foreground font-mono tracking-wide"
      >
        The Bridge Is Watched. Heimdall Never Sleeps.
      </motion.p>
    </div>
  );
}
