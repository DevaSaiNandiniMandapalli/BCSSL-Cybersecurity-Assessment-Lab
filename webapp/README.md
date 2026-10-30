# BCSSL Web Application Security Scanner Lab — Student Platform

A TryHackMe-style student learning platform for the **BCSSL Web Application Security Scanner Lab**,
built for **Blue Cloud Softech Solutions Ltd.** ("Think Big | AI-First").

The platform guides students through seven progressive, hands-on exercises using the Project #08
Web Application Security Scanner against an authorized local OWASP Juice Shop target
(`http://localhost:3001`).

---

## 1. Technology Stack

| Layer     | Technology                          |
|-----------|-------------------------------------|
| Framework | React 18                            |
| Routing   | React Router v6 (hash-based)        |
| Build     | Vite 5                              |
| Styling   | Hand-written CSS design system (no UI framework) |
| State     | React Context + `localStorage`      |
| Language  | JavaScript (JSX, ES modules)        |

No backend is required — the app runs entirely in the browser. Theme preference, progress,
checklist items, lab-note answers, and profile details persist in `localStorage`.

---

## 2. Installation & Running Locally

### Prerequisites

- **Node.js 18+** and **npm** (developed and tested on Node 24 / npm 11)

### Steps

```powershell
# 1. Enter the webapp directory
cd webapp

# 2. Install dependencies
npm install

# 3. Start the development server
npm run dev
```

Then open the printed URL (default: **http://localhost:5173**) in your browser.

### Other commands

```powershell
npm run build     # production build -> dist/
npm run preview   # serve the production build locally (default: http://localhost:4173)
```

> **Note:** the dev server binds to `0.0.0.0` (`host: true`), so the platform is also reachable
> from other devices on your network (e.g. a tablet) via your machine's IP address — useful for
> classroom projection or testing responsive layouts.

---

## 3. Company Logo Asset

The application loads the official **Blue Cloud Softech Solutions Ltd.** logo from:

```
webapp/public/assets/company-logo.png
```

The logo is displayed prominently in the sidebar, dashboard hero, profile/company area, and
footer, on a white chip surface so the blue wordmark stays readable on dark navy surfaces in
both light and dark mode. If the image is missing, the app degrades gracefully to a monogram
tile — no broken images are shown.

---

## 4. Features

- **Light / Dark mode** — sun/moon toggle in the top navigation; deep-navy dark theme;
  preference persists in `localStorage` with no page reload; every surface (cards, tables,
  code blocks, forms, badges, empty states, navigation) adapts
- **Dashboard** — laboratory control-panel layout: product identity with company logo, lab
  status strip (authorized target / application / scope / status), course progress, stat
  cards, authorized target card, "up next" panel
- **Exercises** — all 7 exercises with locked / unlocked / completed states
- **Exercise detail** — full instructional content (objectives, background, tasks with copyable
  PowerShell blocks, lab-note questions with local auto-save, evidence list, interactive
  completion checklist, mark-as-complete flow)
- **Lab Target** — prominent authorized-target card, container start/verify commands,
  authorization scope and prohibited activities
- **Evidence** — per-exercise evidence tracking, naming conventions, honesty requirements
- **Progress** — progress ring, milestones, per-exercise status
- **Profile** — editable student identity with company branding, saved locally, danger-zone reset
- **States** — boot loading screen, skeleton cards, empty states, error states (locked /
  not-found exercises), toast success/error notifications
- **Responsive** — desktop, laptop, tablet (≤900px: collapsible sidebar), and mobile layouts;
  logo and theme controls remain usable at small widths
- **Micro-interactions** — button/card hover, theme cross-fade, animated progress bars,
  navigation active indicator, toast feedback; respects `prefers-reduced-motion`

### Unlock model

Exercise **01 is unlocked by default**. Exercises **02–07 unlock automatically** when the
previous exercise is marked complete. Progress is stored per-browser in `localStorage`.

---

## 5. Project Structure

```
webapp/
├── index.html
├── package.json
├── vite.config.js
├── README.md
├── public/
│   └── assets/
│       └── company-logo.png        ← official BCSSL logo
└── src/
    ├── main.jsx                    # entry point
    ├── App.jsx                     # routes + boot screen
    ├── index.css                   # BCSSL design system (blue / orange / white, light + dark)
    ├── data/
    │   └── exercises.js            # lab + 7 exercises (from official student files)
    ├── context/
    │   ├── ProgressContext.jsx     # progress state, toasts, localStorage persistence
    │   └── ThemeContext.jsx        # light/dark theme, localStorage persistence
    ├── components/
    │   ├── Layout.jsx              # sidebar + topbar (theme toggle) + footer shell
    │   ├── Logo.jsx                # company logo with chip + graceful fallback
    │   ├── Icon.jsx                # consistent stroke icon set
    │   ├── ProgressBar.jsx
    │   ├── ExerciseCard.jsx
    │   ├── TargetCard.jsx          # authorized target card
    │   ├── StatCard.jsx
    │   ├── StatusBadge.jsx
    │   ├── CodeBlock.jsx           # copyable PowerShell blocks
    │   ├── Toast.jsx
    │   └── States.jsx              # skeleton / empty / error states
    └── pages/
        ├── Dashboard.jsx
        ├── Exercises.jsx
        ├── ExerciseDetail.jsx
        ├── LabTarget.jsx
        ├── Evidence.jsx
        ├── Progress.jsx
        └── Profile.jsx
```

---

## 6. Scope & Ethics

This platform is a **local classroom laboratory tool**. All lab activity is authorized **only**
against `http://localhost:3001` (a local OWASP Juice Shop Docker container). The platform
contains instructional content derived from the official BCSSL student exercise files and does
not include any completed student answers or fabricated findings. Scanner findings are
observations, not confirmed vulnerabilities.

© Blue Cloud Softech Solutions Ltd. — BCSSL Web Application Security Scanner Lab.
