package com.devnow.thoryn.cli.cmd.provision

/**
 * SSO-4072 — the body vectors of the server's rules tests, copied from oauthy #4294 (identity-service and product-api
 * `TenantLegalDocumentRulesTest`, head 7c5b802): what each copy of the rule must accept (CommonMark autolinks are Markdown, not
 * HTML) and refuse (`html_not_allowed`). [REFUSED] is the union of the two suites (product-api adds the comment and the end tag).
 * [ACCEPTED_SPACING] is this CLI's own addition: it tells "each autolink becomes a SPACE" apart from "each autolink is removed".
 */
internal object LegalDocumentRulesVectors {
    val ACCEPTED: List<String> = listOf(
        "Questions? Mail <legal@acme.example> or see <https://acme.example/help?a=1&b=2>.",
        "<mailto:privacy@acme.example>",
        "<HTTPS://ACME.EXAMPLE/terms>",
        "Not linked, still not HTML: <http://acme.example> and <tel:+31201234567>.",
        "<javascript:alert(1)>",
        "<first.last+tag@sub.acme-example.co.uk>",
        "a < b, and b > c",
    )

    val REFUSED: List<String> = listOf(
        "See <https://acme.example> and <a href=\"https://acme.example\">this</a>.",
        "<https://acme.example><script>alert(1)</script>",
        "<https://acme.example/<script>",
        "<a:b>",
        "<legal@acme.example onclick=x>",
        "<svg onload=alert(1)>",
        "<!-- comment -->",
        "text </div>",
    )

    /** `a<` + an autolink + `b`: the server's replacement leaves `a< b` (no markup); removing the autolink would leave `a<b` (a tag). */
    const val ACCEPTED_SPACING: String = "a<<https://acme.example>b"
}
