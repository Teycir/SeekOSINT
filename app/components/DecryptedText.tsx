'use client';

import { useState, useEffect, useRef } from 'react';
import { motion } from 'framer-motion';

const CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_+-=[]{}|;:,.<>?';

interface DecryptedTextProps {
  text: string;
  speed?: number;
  maxIterations?: number;
  className?: string;
  animateOn?: 'view' | 'hover';
}

export default function DecryptedText({
  text,
  speed = 50,
  maxIterations = 20,
  className = '',
  animateOn = 'hover',
}: DecryptedTextProps) {
  const [display, setDisplay] = useState(animateOn === 'view' ? '' : text);
  const ref = useRef<HTMLSpanElement>(null);
  const frameRef = useRef(0);

  function scramble() {
    let iter = 0;
    clearInterval(frameRef.current);
    frameRef.current = window.setInterval(() => {
      setDisplay(
        text.split('').map((char, i) => {
          if (i < iter) return char;
          return CHARS[Math.floor(Math.random() * CHARS.length)];
        }).join('')
      );
      if (iter >= text.length) {
        clearInterval(frameRef.current);
        setDisplay(text);
      }
      iter += 1;
    }, speed);
  }

  useEffect(() => {
    if (animateOn !== 'view') return;
    const observer = new IntersectionObserver(
      ([entry]) => { if (entry?.isIntersecting) { observer.disconnect(); scramble(); } },
      { threshold: 0.1 }
    );
    if (ref.current) observer.observe(ref.current);
    return () => { observer.disconnect(); clearInterval(frameRef.current); };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <motion.span
      ref={ref}
      className={`inline-block ${className}`}
      onMouseEnter={() => animateOn === 'hover' && scramble()}
    >
      {display || text}
    </motion.span>
  );
}
