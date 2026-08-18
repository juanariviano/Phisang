/**
 * The inspection bench. A cutting-mat grid rather than gradient blobs or a
 * fruit texture: this is the surface you put a suspect thing down on and look
 * at it. Nearly invisible by design — it should register as order, not decor.
 */
export function Bench() {
  return <div aria-hidden="true" className="bench pointer-events-none fixed inset-0 -z-10" />;
}
