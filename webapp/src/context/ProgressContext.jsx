import { createContext, useContext, useEffect, useMemo, useState, useCallback } from 'react';
import { EXERCISES } from '../data/exercises.js';

const ProgressContext = createContext(null);

const STORAGE_KEY = 'bcssl-cyber-lab-progress-v2';
const PROFILE_KEY = 'bcssl-cyber-lab-profile-v1';

const defaultState = {
  completed: [],          // array of exercise ids the student has marked complete
  completedAt: {},        // { [exerciseId]: ISO timestamp of legitimate completion }
  checklist: {},          // { [exerciseId]: { [itemIndex]: bool } }
  answers: {},            // { [exerciseId]: { [questionIndex]: string } }
  evidence: {},           // { [exerciseId]: { [itemIndex]: bool } }
  checked: {},            // { [exerciseId]: { [questionIndex]: { passed: bool, checkedAt: string } } }
};

const defaultProfile = {
  name: '',
  studentId: '',
  email: '',
  cohort: '',
};

function loadState() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return defaultState;
    const parsed = JSON.parse(raw);
    return { ...defaultState, ...parsed };
  } catch {
    return defaultState;
  }
}

function loadProfile() {
  try {
    const raw = localStorage.getItem(PROFILE_KEY);
    if (!raw) return defaultProfile;
    return { ...defaultProfile, ...JSON.parse(raw) };
  } catch {
    return defaultProfile;
  }
}

export function ProgressProvider({ children }) {
  const [state, setState] = useState(loadState);
  const [profile, setProfile] = useState(loadProfile);
  const [toast, setToast] = useState(null);

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  }, [state]);

  useEffect(() => {
    localStorage.setItem(PROFILE_KEY, JSON.stringify(profile));
  }, [profile]);

  const showToast = useCallback((message, type = 'success') => {
    const id = Date.now() + Math.random();
    setToast({ id, message, type });
    setTimeout(() => {
      setToast((current) => (current && current.id === id ? null : current));
    }, 3600);
  }, []);

  // Exercise 01 is unlocked by default. Exercise N is unlocked when N-1 is complete.
  const isUnlocked = useCallback(
    (exerciseId) => {
      if (exerciseId === 1) return true;
      return state.completed.includes(exerciseId - 1);
    },
    [state.completed]
  );

  const isCompleted = useCallback(
    (exerciseId) => state.completed.includes(exerciseId),
    [state.completed]
  );

  const completeExercise = useCallback(
    (exerciseId) => {
      setState((prev) => {
        if (prev.completed.includes(exerciseId)) return prev;
        return {
          ...prev,
          completed: [...prev.completed, exerciseId],
          completedAt: { ...prev.completedAt, [exerciseId]: new Date().toISOString() },
        };
      });
      const ex = EXERCISES.find((e) => e.id === exerciseId);
      const next = EXERCISES.find((e) => e.id === exerciseId + 1);
      if (next) {
        showToast(`Exercise ${ex.number} complete — Exercise ${next.number} unlocked`, 'success');
      } else {
        showToast(`Exercise ${ex.number} complete — all exercises finished!`, 'success');
      }
    },
    [showToast]
  );

  const uncompleteExercise = useCallback((exerciseId) => {
    setState((prev) => {
      const completedAt = { ...prev.completedAt };
      delete completedAt[exerciseId];
      return {
        ...prev,
        completed: prev.completed.filter((id) => id !== exerciseId),
        completedAt,
      };
    });
  }, []);

  const toggleChecklistItem = useCallback((exerciseId, itemIndex) => {
    setState((prev) => {
      const exItems = prev.checklist[exerciseId] || {};
      return {
        ...prev,
        checklist: {
          ...prev.checklist,
          [exerciseId]: { ...exItems, [itemIndex]: !exItems[itemIndex] },
        },
      };
    });
  }, []);

  const saveAnswer = useCallback((exerciseId, questionIndex, value) => {
    setState((prev) => {
      const exAnswers = prev.answers[exerciseId] || {};
      return {
        ...prev,
        answers: {
          ...prev.answers,
          [exerciseId]: { ...exAnswers, [questionIndex]: value },
        },
      };
    });
  }, []);

  const checkAnswer = useCallback((exerciseId, questionIndex, passed) => {
    setState((prev) => {
      const exChecked = prev.checked[exerciseId] || {};
      return {
        ...prev,
        checked: {
          ...prev.checked,
          [exerciseId]: {
            ...exChecked,
            [questionIndex]: { passed, checkedAt: new Date().toISOString() },
          },
        },
      };
    });
  }, []);

  const resetCheck = useCallback((exerciseId, questionIndex) => {
    setState((prev) => {
      const exChecked = prev.checked[exerciseId] || {};
      const newExChecked = { ...exChecked };
      delete newExChecked[questionIndex];
      return {
        ...prev,
        checked: {
          ...prev.checked,
          [exerciseId]: newExChecked,
        },
      };
    });
  }, []);

  const toggleEvidenceItem = useCallback((exerciseId, itemIndex) => {
    setState((prev) => {
      const exItems = prev.evidence[exerciseId] || {};
      return {
        ...prev,
        evidence: {
          ...prev.evidence,
          [exerciseId]: { ...exItems, [itemIndex]: !exItems[itemIndex] },
        },
      };
    });
  }, []);

  const updateProfile = useCallback((updates) => {
    setProfile((prev) => ({ ...prev, ...updates }));
  }, []);

  const resetAll = useCallback(() => {
    setState(defaultState);
    setProfile(defaultProfile);
    localStorage.removeItem(STORAGE_KEY);
    localStorage.removeItem(PROFILE_KEY);
    showToast('All progress has been reset', 'info');
  }, [showToast]);

  const stats = useMemo(() => {
    const total = EXERCISES.length;
    const done = state.completed.length;
    const pct = Math.round((done / total) * 100);

    let checklistTotal = 0;
    let checklistDone = 0;
    EXERCISES.forEach((ex) => {
      ex.checklist.forEach((_, i) => {
        checklistTotal += 1;
        if (state.checklist[ex.id]?.[i]) checklistDone += 1;
      });
    });

    let evidenceTotal = 0;
    let evidenceDone = 0;
    EXERCISES.forEach((ex) => {
      ex.evidence.forEach((_, i) => {
        evidenceTotal += 1;
        if (state.evidence[ex.id]?.[i]) evidenceDone += 1;
      });
    });

    return { total, done, pct, checklistTotal, checklistDone, evidenceTotal, evidenceDone };
  }, [state]);

  const value = {
    state,
    profile,
    stats,
    toast,
    showToast,
    isUnlocked,
    isCompleted,
    completeExercise,
    uncompleteExercise,
    toggleChecklistItem,
    saveAnswer,
    checkAnswer,
    resetCheck,
    toggleEvidenceItem,
    updateProfile,
    resetAll,
  };

  return <ProgressContext.Provider value={value}>{children}</ProgressContext.Provider>;
}

export function useProgress() {
  const ctx = useContext(ProgressContext);
  if (!ctx) throw new Error('useProgress must be used within ProgressProvider');
  return ctx;
}
