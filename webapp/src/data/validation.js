// ============================================================
// BCSSL Web Application Security Scanner Lab — Answer validation
//
// TRYHACKME-STYLE KEYWORD VALIDATION — NO ANSWER KEY IN UI.
//
// Each question has a structured answer definition with:
//   type:    "keyword" | "keywords" | "yesno" | "number" | "list"
//   answers: array of required keywords (case-insensitive)
//   aliases: optional accepted aliases
//
// The student sees only the format hint — never the expected answer.
// Validation is local-only: no network, no AI service.
// ============================================================

// Normalize text for comparison: lowercase, trim, collapse whitespace,
// normalize hyphens and punctuation.
function normalize(text) {
  return (text || '')
    .toLowerCase()
    .replace(/[’‘]/g, "'")
    .replace(/[“”]/g, '"')
    .replace(/[–—]/g, '-')
    .replace(/[^a-z0-9'\s.\/:;+_-]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

// Split a multi-answer string into individual items.
// Accepts separators: ; , / newline
function splitAnswers(text) {
  return text
    .split(/[;,\/\n]+/)
    .map((s) => normalize(s))
    .filter((s) => s.length > 0);
}

// Check if a normalized answer matches any of the required answers or aliases.
// Uses includes() so that longer answers containing the keyword also pass.
function matchesKeyword(normalizedAnswer, requiredList) {
  return requiredList.some((req) => {
    const normalizedReq = normalize(req);
    return normalizedAnswer.includes(normalizedReq);
  });
}

// Check if ALL required keywords are present in the answer.
function containsAllKeywords(normalizedAnswer, requiredList) {
  return requiredList.every((req) => normalizedAnswer.includes(req));
}

// Extract the first number from text.
function extractNumber(text) {
  const match = text.match(/\d+/);
  return match ? match[0] : null;
}

/**
 * Validate a single answer against its question definition.
 * Returns { passed: boolean, feedback: string }.
 * Never reveals the expected answer.
 */
export function validateAnswer(rawAnswer, question) {
  const text = (rawAnswer || '').trim();
  if (!text) {
    return { passed: false, feedback: 'Please enter an answer before checking.' };
  }

  const norm = normalize(text);
  const type = question.type || 'keyword';
  const answers = question.answers || [];
  const aliases = question.aliases || [];
  const allAccepted = [...answers, ...aliases];

  switch (type) {
    case 'keyword': {
      // Single keyword match — answer must match one of the accepted keywords
      if (matchesKeyword(norm, allAccepted)) {
        return { passed: true, feedback: 'Correct' };
      }
      return { passed: false, feedback: 'Needs correction — review the exercise evidence and try again.' };
    }

    case 'keywords': {
      // Multiple keywords — ALL must be present in the answer
      if (containsAllKeywords(norm, answers)) {
        return { passed: true, feedback: 'Correct' };
      }
      return { passed: false, feedback: 'Needs correction — review the exercise evidence and try again.' };
    }

    case 'yesno': {
      // YES/NO answer
      const upper = text.toUpperCase();
      if (upper === 'YES' || upper === 'NO') {
        if (answers.length === 0 || upper === answers[0].toUpperCase()) {
          return { passed: true, feedback: 'Correct' };
        }
      }
      return { passed: false, feedback: 'Needs correction — review the exercise evidence and try again.' };
    }

    case 'number': {
      // Numeric answer
      const num = extractNumber(text);
      if (num !== null && answers.includes(num)) {
        return { passed: true, feedback: 'Correct' };
      }
      return { passed: false, feedback: 'Needs correction — review the exercise evidence and try again.' };
    }

    case 'list': {
      // List of items — split answer and check all required are present
      const parts = splitAnswers(text);
      const allPresent = answers.every((req) =>
        parts.some((part) => part === req || part.includes(req))
      );
      if (allPresent) {
        return { passed: true, feedback: 'Correct' };
      }
      return { passed: false, feedback: 'Needs correction — review the exercise evidence and try again.' };
    }

    case 'structured': {
      // Multi-field: each field has its own accepted answers
      const fields = question.fields || [];
      const allFieldsPassed = fields.every((field) => {
        const fieldAnswers = [...field.answers, ...(field.aliases || [])];
        return matchesKeyword(norm, fieldAnswers) || containsAllKeywords(norm, fieldAnswers);
      });
      if (allFieldsPassed) {
        return { passed: true, feedback: 'Correct' };
      }
      return { passed: false, feedback: 'Needs correction — review the exercise evidence and try again.' };
    }

    default:
      return { passed: false, feedback: 'Needs correction — review the exercise evidence and try again.' };
  }
}

/**
 * Validate every question of an exercise.
 * `answers` is the stored map { [questionIndex]: string }.
 * Returns per-question results plus a summary. Never reveals answers.
 */
export function validateExerciseQuestions(exerciseId, answers, questions) {
  const results = questions.map((question, i) => {
    const answer = answers?.[i] || '';
    const { passed } = validateAnswer(answer, question);
    return { index: i, passed, answered: answer.trim().length > 0 };
  });

  const total = results.length;
  const passedCount = results.filter((r) => r.passed).length;
  const failed = results.filter((r) => !r.passed);

  return {
    total,
    passedCount,
    failed,
    allPassed: total > 0 && failed.length === 0,
  };
}
