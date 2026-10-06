// dweb LibreWolf profile.
//
// This profile is only for the decentralised web. Every request goes to the
// local resolver on 127.0.0.1, which looks names up in the registry and
// verifies each site against its owner's key. It never falls back to normal
// DNS, so ordinary websites will not load here; use your normal browser for
// those. The resolver's local certificate authority is trusted by this
// profile only.

// Send all traffic to the local resolver.
user_pref("network.proxy.type", 1);
user_pref("network.proxy.http", "127.0.0.1");
user_pref("network.proxy.http_port", 7780);
user_pref("network.proxy.ssl", "127.0.0.1");
user_pref("network.proxy.ssl_port", 7780);
user_pref("network.proxy.share_proxy_settings", true);
user_pref("network.proxy.no_proxies_on", "");
user_pref("network.proxy.failover_direct", false);

// No DNS of any kind from the browser: no DNS-over-HTTPS, no prefetching.
user_pref("network.trr.mode", 5);
user_pref("network.dns.disablePrefetch", true);
user_pref("network.dns.disablePrefetchFromHTTPS", true);
user_pref("network.predictor.enabled", false);
user_pref("network.prefetch-next", false);
user_pref("network.http.speculative-parallel-limit", 0);

// Typing "alice.xyz" should visit it, not search for it.
user_pref("keyword.enabled", false);
user_pref("browser.fixup.alternate.enabled", false);
user_pref("browser.urlbar.suggest.searches", false);
user_pref("browser.search.suggest.enabled", false);
user_pref("browser.fixup.dns_first_for_single_words", false);

// Always use HTTPS to sites; the resolver serves it with the local CA.
user_pref("dom.security.https_only_mode", true);
user_pref("dom.security.https_only_mode_send_http_background_request", false);

// Do not trust the operating system's certificate store in this profile.
user_pref("security.enterprise_roots.enabled", false);

// Nothing should bypass the proxy and reveal your address.
user_pref("media.peerconnection.enabled", false);
user_pref("network.captive-portal-service.enabled", false);
user_pref("network.connectivity-service.enabled", false);

// Start page: the resolver's status page.
user_pref("browser.startup.homepage", "http://127.0.0.1:7780/");
user_pref("browser.startup.page", 1);
