// ============================================================
// BCSSL Web Application Security Scanner Lab — Achievement badges
// Badges are DERIVED from exercise completion state. A badge is
// awarded when its exercise is legitimately marked complete via
// the exercise completion flow. The Master Badge requires all
// seven exercises completed. Nothing here fabricates completion.
// ============================================================

export const BADGES = [
  {
    id: 1,
    exerciseId: 1,
    number: '01',
    name: 'First Scan',
    description: 'You completed Exercise 01 — Web Security Scanner.',
    icon: 'scanner',
  },
  {
    id: 2,
    exerciseId: 2,
    number: '02',
    name: 'Header Analyst',
    description: 'You completed Exercise 02 — HTTP Security Headers.',
    icon: 'shield',
  },
  {
    id: 3,
    exerciseId: 3,
    number: '03',
    name: 'Path Explorer',
    description: 'You completed Exercise 03 — Path Discovery.',
    icon: 'radar',
  },
  {
    id: 4,
    exerciseId: 4,
    number: '04',
    name: 'Injection Indicator Analyst',
    description: 'You completed Exercise 04 — Safe Injection Indicators.',
    icon: 'syringe',
  },
  {
    id: 5,
    exerciseId: 5,
    number: '05',
    name: 'Configuration Reviewer',
    description: 'You completed Exercise 05 — Configuration Weaknesses.',
    icon: 'sliders',
  },
  {
    id: 6,
    exerciseId: 6,
    number: '06',
    name: 'Burp Verification',
    description: 'You completed Exercise 06 — Burp Suite Verification.',
    icon: 'crosshair',
  },
  {
    id: 7,
    exerciseId: 7,
    number: '07',
    name: 'Evidence Compiler',
    description: 'You completed Exercise 07 — Evidence and Screenshots.',
    icon: 'folder',
  },
];

export const MASTER_BADGE = {
  id: 'master',
  number: 'M',
  name: 'BCSSL Web Application Security Scanner Lab',
  title: 'MASTER BADGE',
  description: 'You completed all 7 lab exercises.',
  icon: 'award',
};

export const TOTAL_BADGES = BADGES.length + 1; // 7 exercise badges + 1 master badge

// --- Pure helpers (no side effects) ---

export function isBadgeUnlocked(badge, completed) {
  return completed.includes(badge.exerciseId);
}

export function isMasterUnlocked(completed) {
  return BADGES.every((b) => completed.includes(b.exerciseId));
}

export function unlockedBadgeCount(completed) {
  const earned = BADGES.filter((b) => completed.includes(b.exerciseId)).length;
  return isMasterUnlocked(completed) ? earned + 1 : earned;
}

export function formatCompletionDate(isoString) {
  if (!isoString) return null;
  try {
    const d = new Date(isoString);
    return d.toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  } catch {
    return null;
  }
}
