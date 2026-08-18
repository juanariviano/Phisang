chrome.runtime.sendMessage({ type: "GET_TAB_RESULT" }, (payload) => {
  const result = payload?.result;
  if (!result || result.classification !== "unavailable") return;
  if (document.getElementById("linkguard-banner")) return;

  const banner = document.createElement("div");
  banner.id = "linkguard-banner";
  banner.setAttribute("role", "status");
  banner.style.cssText = [
    "position:fixed",
    "top:0",
    "left:0",
    "right:0",
    "z-index:2147483647",
    "background:#1c1c20",
    "color:#f3f1ec",
    "font:13px/1.45 Outfit,Segoe UI,system-ui,sans-serif",
    "padding:12px 16px",
    "border-bottom:1px solid rgba(184,92,78,.45)",
  ].join(";");
  banner.textContent =
    "LinkGuard: threat feed or model unreachable — this is a degraded result, not a clean one.";
  document.documentElement.prepend(banner);
});
