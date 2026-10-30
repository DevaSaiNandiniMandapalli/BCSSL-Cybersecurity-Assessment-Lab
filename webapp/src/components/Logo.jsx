import { useState } from 'react';

// Renders the official Blue Cloud Softech Solutions Ltd. logo from
// /assets/company-logo.png. Aspect ratio is always preserved (height
// driven by size class, width auto). If the image is missing, the
// component degrades gracefully to a monogram tile + wordmark.
//
// Sizes: sm=40px  md=56px  lg=72px  xl=88px (scaled down on mobile)
// chip=true wraps the logo in a white surface so the blue wordmark
// stays readable on dark navy surfaces in both themes.
const SIZES = ['sm', 'md', 'lg', 'xl'];

// Bump this whenever the source asset is replaced so browsers fetch the
// fresh file instead of serving a stale cached copy. The source asset
// itself always remains company-logo.png.
const LOGO_VERSION = 3;

export default function Logo({ size = 'md', chip = false }) {
  const [failed, setFailed] = useState(false);
  const sizeClass = SIZES.includes(size) ? size : 'md';

  if (failed) {
    return (
      <div className="flex-center" style={{ gap: 10 }}>
        <div className="brand-fallback logo-fallback-md">BC</div>
        <div className="brand-text">
          <div className="brand-name">BCSSL Cyber Lab</div>
          <div className="brand-tag">Blue Cloud Softech Solutions</div>
        </div>
      </div>
    );
  }

  const img = (
    <img
      src={`/assets/company-logo.png?v=${LOGO_VERSION}`}
      alt="Blue Cloud Softech Solutions Ltd. — Think Big | AI-First"
      onError={() => setFailed(true)}
      className={`logo-img logo-${sizeClass}`}
    />
  );

  return chip ? <div className="logo-chip">{img}</div> : img;
}
