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
    "background:#3b2d78",
    "color:#f4efe4",
    "font:13px/1.4 Segoe UI,system-ui,sans-serif",
    "padding:10px 16px",
    "box-shadow:0 8px 24px rgba(0,0,0,.25)",
  ].join(";");
  banner.textContent =
    "LinkGuard: threat feed or model unreachable — this is a degraded result, not a clean one.";
  document.documentElement.prepend(banner);
});
