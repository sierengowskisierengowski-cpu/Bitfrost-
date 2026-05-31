export const BifrostLogo = ({ className = "" }: { className?: string }) => (
  <svg viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg" className={className}>
    <defs>
      <linearGradient id="rainbow" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0%" stopColor="#7B2FBE" />
        <stop offset="20%" stopColor="#9D4EDD" />
        <stop offset="40%" stopColor="#C4607A" />
        <stop offset="60%" stopColor="#E040FB" />
        <stop offset="80%" stopColor="#E91E8C" />
        <stop offset="100%" stopColor="#F48FB1" />
      </linearGradient>
    </defs>
    <path d="M 20 80 Q 50 20 80 80" stroke="url(#rainbow)" strokeWidth="8" strokeLinecap="round" />
    <path d="M 30 80 Q 50 40 70 80" stroke="url(#rainbow)" strokeWidth="4" strokeLinecap="round" opacity="0.6" />
    <circle cx="50" cy="20" r="4" fill="#E040FB" />
  </svg>
);
