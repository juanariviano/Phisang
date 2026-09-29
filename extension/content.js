chrome.runtime.sendMessage({ type: "GET_TAB_RESULT" }, (payload) => {
  const result = payload && payload.result;
  if (!result || result.classification !== "unavailable") return;
  if (document.getElementById("phisang-banner")) return;

  const banner = document.createElement("div");
  banner.id = "phisang-banner";
  banner.setAttribute("role", "status");
  banner.style.cssText = [
    "all:initial",
    "position:fixed",
    "top:0",
    "left:0",
    "right:0",
    "z-index:2147483647",
    "display:block",
    "box-sizing:border-box",
    "background:#FDF5B4",
    "color:#16210F",
    "font:600 13px/1.45 'Public Sans',Segoe UI,system-ui,sans-serif",
    "padding:11px 16px",
    "border-bottom:2.5px solid #16210F",
    // The risk-unknown state carries a hatch everywhere else in Phisang; carry it
    // here too, so the banner is not signalling with colour alone.
    "background-image:repeating-linear-gradient(45deg,rgba(70,114,53,.3) 0 1.5px,transparent 1.5px 8px)",
  ].join(";");
  banner.textContent =
    "Phisang: Risk unknown — the threat feed or model was unreachable. This is a degraded result, not a clean one.";
  document.documentElement.prepend(banner);
});
