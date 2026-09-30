export function Pipeline() {
  return <section className="rounded-xl border-[2.5px] border-ink bg-paper p-6 md:p-7">
    <h2 className="font-display text-2xl font-extrabold tracking-tight text-ink">A little checking before clicking.</h2>
    <ul className="mt-5 divide-y divide-leaf/30 text-sm leading-relaxed text-forest">
      <li className="py-3">Check for known threats and suspicious website details.</li>
      <li className="py-3">See a preview when the page can be inspected.</li>
      <li className="py-3">Ask for a plain-language explanation of the result.</li>
    </ul>
    <p className="mt-5 text-xs leading-relaxed text-leaf">Scanned websites open on our server, not in your browser. No automated check can guarantee a website is safe.</p>
  </section>;
}
