import { useState } from 'react';
import Icon from './Icon.jsx';
import { useProgress } from '../context/ProgressContext.jsx';
import { validateExerciseQuestions } from '../data/validation.js';

// Completion validation dialog.
//
// "Mark as Complete" opens this dialog — it never completes anything by
// itself. The exercise is completed ONLY through onComplete(), which the
// parent wires to the existing completeExercise() after this dialog
// reports a passed validation.
//
// States shown to the student:
//   requirements incomplete → "not ready for completion"
//   validation passed       → "requirements verified" + final complete button
//   validation failed       → exactly what needs correction (no answers revealed)
export default function ValidationDialog({ exercise, onClose, onComplete }) {
  const { state } = useProgress();
  const [verified, setVerified] = useState(null); // null | true | false

  const checklistState = state.checklist[exercise.id] || {};
  const evidenceState = state.evidence[exercise.id] || {};
  const checkedState = state.checked[exercise.id] || {};

  const checklistDone = exercise.checklist.filter((_, i) => checklistState[i]).length;
  const evidenceDone = exercise.evidence.filter((_, i) => evidenceState[i]).length;

  // Questions requirement: every question must have been checked AND passed
  const questionValidation = validateExerciseQuestions(exercise.id, state.answers[exercise.id] || {}, exercise.questions);
  const questionsPassed = questionValidation.passedCount;
  const allQuestionsPassed = questionValidation.allPassed;

  const requirementsMet =
    checklistDone === exercise.checklist.length &&
    allQuestionsPassed &&
    evidenceDone === exercise.evidence.length;

  const handleVerify = () => {
    setVerified(requirementsMet);
  };

  return (
    <div className="badge-modal-overlay" onClick={onClose} role="dialog" aria-modal="true" aria-label="Completion validation">
      <div className="badge-modal validation-modal" onClick={(e) => e.stopPropagation()}>
        <button className="badge-modal-close" onClick={onClose} aria-label="Close">
          <Icon name="x" size={18} />
        </button>

        <div className="validation-modal-icon">
          <Icon name={verified === false ? 'alert-octagon' : 'shield'} size={30} />
        </div>

        <div className="badge-modal-eyebrow">COMPLETION VALIDATION</div>
        <h2 className="badge-modal-name">Before completing Exercise {exercise.number}</h2>

        {/* Requirement rows */}
        <div className="validation-requirements">
          <div className={`validation-row ${checklistDone === exercise.checklist.length ? 'ok' : 'pending'}`}>
            <span className="validation-row-icon">
              <Icon name={checklistDone === exercise.checklist.length ? 'check-circle' : 'clock'} size={17} />
            </span>
            <span className="validation-row-label">Checklist</span>
            <span className="validation-row-value">
              {checklistDone === exercise.checklist.length ? 'complete' : `${checklistDone}/${exercise.checklist.length} items`}
            </span>
          </div>

          <div className={`validation-row ${allQuestionsPassed ? 'ok' : 'pending'}`}>
            <span className="validation-row-icon">
              <Icon name={allQuestionsPassed ? 'check-circle' : 'clock'} size={17} />
            </span>
            <span className="validation-row-label">Questions</span>
            <span className="validation-row-value">
              {allQuestionsPassed
                ? 'complete'
                : `${questionsPassed}/${exercise.questions.length} accepted`}
            </span>
          </div>

          <div className={`validation-row ${evidenceDone === exercise.evidence.length ? 'ok' : 'pending'}`}>
            <span className="validation-row-icon">
              <Icon name={evidenceDone === exercise.evidence.length ? 'check-circle' : 'clock'} size={17} />
            </span>
            <span className="validation-row-label">Evidence</span>
            <span className="validation-row-value">
              {evidenceDone === exercise.evidence.length ? 'complete' : `${evidenceDone}/${exercise.evidence.length} items`}
            </span>
          </div>
        </div>

        {/* Result states */}
        {verified === true && (
          <div className="validation-result success">
            <Icon name="check-circle" size={18} />
            <span>Exercise {exercise.number} requirements verified.</span>
          </div>
        )}

        {verified === false && (
          <div className="validation-result failure">
            <div className="validation-result-title">
              Exercise {exercise.number} is not ready for completion.
            </div>
            <ul className="validation-summary">
              <li className={checklistDone === exercise.checklist.length ? 'ok' : 'bad'}>
                {checklistDone === exercise.checklist.length ? '✓' : '✗'} Checklist:{' '}
                {checklistDone === exercise.checklist.length ? 'complete' : 'incomplete'}
              </li>
              <li className={allQuestionsPassed ? 'ok' : 'bad'}>
                {allQuestionsPassed ? '✓' : '✗'} Questions:{' '}
                {allQuestionsPassed
                  ? 'complete'
                  : `${exercise.questions.length - questionsPassed} answers need correction`}
              </li>
              <li className={evidenceDone === exercise.evidence.length ? 'ok' : 'bad'}>
                {evidenceDone === exercise.evidence.length ? '✓' : '✗'} Evidence:{' '}
                {evidenceDone === exercise.evidence.length ? 'complete' : 'incomplete'}
              </li>
            </ul>
            {failedQuestions.length > 0 && (
              <div className="validation-hint">
                Correct the highlighted answers before completing this exercise.
                {failedQuestions.length > 0 && (
                  <span className="validation-questions"> ({failedQuestions.join(', ')})</span>
                )}
              </div>
            )}
          </div>
        )}

        {/* Actions */}
        <div className="validation-actions">
          {verified === true ? (
            <button className="btn btn-primary btn-lg btn-block" onClick={onComplete}>
              <Icon name="check-circle" size={17} />
              Complete Exercise {exercise.number}
            </button>
          ) : (
            <>
              <button className="btn btn-blue btn-block" onClick={handleVerify} disabled={!requirementsMet}>
                <Icon name="shield" size={16} />
                Verify Requirements
              </button>
              <button className="btn btn-ghost btn-block" onClick={onClose}>
                Keep Working
              </button>
            </>
          )}
        </div>

        {verified !== true && !requirementsMet && (
          <p className="validation-note">
            {evidenceDone < exercise.evidence.length
              ? 'Acknowledge all required evidence items before completing this exercise.'
              : 'Complete the checklist and answer every question — then verify.'}
          </p>
        )}
      </div>
    </div>
  );
}
