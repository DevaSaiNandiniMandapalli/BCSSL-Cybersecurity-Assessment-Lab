import { useState } from 'react';
import Icon from './Icon.jsx';
import { validateAnswer } from '../data/validation.js';

// Per-question answer field with Check button, immediate feedback, and a
// 4-state status indicator.
//
// Status states:
//   not-answered       → empty, never checked
//   answered-unchecked  → has text, not yet checked (or edited since last check)
//   correct            → checked and passed
//   needs-correction   → checked and failed
//
// The Check button runs keyword-based validation against the question's
// answer definition. Feedback never reveals the expected answer.

const STATUS_META = {
  'not-answered': { label: 'Not answered', icon: 'clock' },
  'answered-unchecked': { label: 'Answered — not checked', icon: 'check' },
  'correct': { label: 'Correct', icon: 'check-circle' },
  'needs-correction': { label: 'Needs correction', icon: 'alert-triangle' },
};

function isShortAnswer(question) {
  const type = question.type || 'keyword';
  return type === 'keyword' || type === 'yesno' || type === 'number';
}

export default function QuestionField({
  id,
  index,
  question,
  answer,
  checked,
  onSave,
  onCheck,
  onResetCheck,
}) {
  const [feedback, setFeedback] = useState(null);

  const hasText = answer.trim().length > 0;
  const isChecked = checked !== undefined;
  const isCorrect = checked?.passed === true;

  let status = 'not-answered';
  if (hasText && !isChecked) status = 'answered-unchecked';
  else if (isChecked && isCorrect) status = 'correct';
  else if (isChecked && !isCorrect) status = 'needs-correction';

  const meta = STATUS_META[status];
  const shortAnswer = isShortAnswer(question);

  const handleCheck = () => {
    const result = validateAnswer(answer, question);
    onCheck(result.passed);
    setFeedback(result);
  };

  const handleChange = (value) => {
    onSave(value);
    if (isChecked) onResetCheck();
    setFeedback(null);
  };

  return (
    <div className="field question-field">
      <div className="question-label-row">
        <label htmlFor={`q-${id}-${index}`}>
          <span className="text-orange" style={{ fontWeight: 700 }}>Q{index + 1}.</span> {question.q}
        </label>
        <span className={`answer-status status-${status}`}>
          <Icon name={meta.icon} size={13} />
          {meta.label}
        </span>
      </div>

      {shortAnswer ? (
        <input
          id={`q-${id}-${index}`}
          className="input"
          type="text"
          placeholder="Type your answer..."
          value={answer}
          onChange={(e) => handleChange(e.target.value)}
        />
      ) : (
        <textarea
          id={`q-${id}-${index}`}
          className="textarea"
          placeholder="Type your answer..."
          value={answer}
          onChange={(e) => handleChange(e.target.value)}
        />
      )}

      <div className="answer-format-hint">
        <span className="answer-format-label">ANSWER FORMAT</span>
        <span className="answer-format-value">{question.format}</span>
      </div>

      <div className="question-actions">
        <button
          className="btn btn-blue btn-sm check-btn"
          onClick={handleCheck}
          disabled={!hasText}
        >
          <Icon name="shield" size={14} />
          Check
        </button>
      </div>

      {feedback && (
        <div className={`answer-feedback ${feedback.passed ? 'correct' : 'needs-correction'}`}>
          <Icon name={feedback.passed ? 'check-circle' : 'alert-triangle'} size={15} />
          <span>{feedback.feedback}</span>
        </div>
      )}
    </div>
  );
}
