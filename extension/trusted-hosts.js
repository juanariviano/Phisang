/* Hosts the extension does not hold the tab for at all.

   A search engine is navigated dozens of times an hour, and every one of those
   navigations costs a visible flash of the checking screen to deliver a verdict
   nobody needed. These hosts skip interception entirely: no checking screen, no
   API request, no database lookup, no cache read.

   The match is the EXACT hostname (a leading "www." aside), never the registered
   domain. That distinction is the whole safety of this list: `google.com` is a
   search engine, while `sites.google.com`, `docs.google.com`, `drive.google.com`
   and `firebasestorage.googleapis.com` serve pages anyone can author and are
   routinely used to host phishing. Matching two labels would clear all of them.

   The server's own well-known list (app/reputation.py) is deliberately separate
   and means something weaker: skip the page fetch, after the threat feed has
   already run. Nothing here reaches the server at all, so this list stays short
   and holds only hosts whose operator does not publish other people's pages.

   A navigation away from one of these hosts is a new navigation, so clicking a
   search result is still checked. */
(function () {
  const TRUSTED = new Set([
    // Search
    'google.com', 'google.co.id', 'google.co.uk', 'google.ca', 'google.com.au',
    'google.de', 'google.fr', 'google.es', 'google.it', 'google.nl', 'google.pl',
    'google.co.jp', 'google.co.kr', 'google.com.sg', 'google.com.my',
    'google.com.ph', 'google.co.th', 'google.com.vn', 'google.com.br',
    'google.com.mx', 'google.co.in',
    'bing.com', 'duckduckgo.com', 'search.yahoo.com', 'ecosia.org',
    'startpage.com', 'search.brave.com', 'baidu.com', 'yandex.com',
    // Signed-in apps on hosts that publish nobody else's pages
    'mail.google.com', 'calendar.google.com', 'meet.google.com',
    'outlook.office.com', 'outlook.live.com',
    // Media and reference
    'youtube.com', 'm.youtube.com', 'music.youtube.com',
    'en.wikipedia.org', 'id.wikipedia.org', 'wikipedia.org',
  ]);

  function trustedHost(url) {
    try {
      const parsed = new URL(url);
      if (!['http:', 'https:'].includes(parsed.protocol)) return false;
      let host = parsed.hostname.toLowerCase().replace(/\.$/, '');
      // Only this one prefix is folded away; every other label must match as
      // written, so a subdomain never inherits its parent's trust.
      if (host.startsWith('www.')) host = host.slice(4);
      return TRUSTED.has(host);
    } catch {
      return false;
    }
  }

  Object.assign(self.Phisang ||= {}, { trustedHost, TRUSTED_HOSTS: TRUSTED });
})();
