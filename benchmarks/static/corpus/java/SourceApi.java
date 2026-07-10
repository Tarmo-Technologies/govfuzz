// Best-in-class: taint from real INPUT-SOURCE APIs, not just parameter names.
// `handle`'s parameter is named `req` (not a source-name), so the ONLY reason the
// flow is caught is that `req.getParameter(...)` is a recognized attacker-input
// source — the difference between name-based taint and finding real framework bugs.
class SourceApi {
    void handle(HttpServletRequest req) throws Exception {
        String p = req.getParameter("cmd");
        Runtime.getRuntime().exec(p);        // EXPECT GF-304
    }
}
