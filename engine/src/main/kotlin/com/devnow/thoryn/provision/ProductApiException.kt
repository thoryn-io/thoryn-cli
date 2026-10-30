package com.devnow.thoryn.provision

import tools.jackson.databind.ObjectMapper
import tools.jackson.module.kotlin.readValue

/**
 * Thrown when the product-api returns a non-2xx response.
 *
 * Two error wire shapes are surfaced, both reduced to (`errorCode`,
 * `errorDescription`):
 *  - RFC 6749 §5.2 OAuth bodies (`error` + `error_description`) from the hub's
 *    token / device endpoints.
 *  - RFC 9457 problem-details (`errorCode` + `detail`, plus `title`) that
 *    product-api's `ProblemDetailsWriter` emits across the customer plane
 *    (SSO-1122) — `/api/v1/applications`, `/federation-members`, `/audit/[*]`.
 *
 * The CLI surfaces both — the code so we can route to a "run `oathy login
 * --scope …`" hint, the description so the user sees the human-readable reason.
 *
 * SSO-3662: lives in the engine library (the engine branches on `httpStatus` / `errorCode`); the CLI
 * reaches it through the `com.devnow.thoryn.cli.api.ProductApiException` typealias.
 */
class ProductApiException(
    val httpStatus: Int,
    /** OAuth2 error code, or null if the body wasn't OAuth2-shaped. */
    val errorCode: String?,
    val errorDescription: String?,
    /** Raw body for `--output json` structured-error reporting. */
    val rawBody: String,
    /** SSO-3396 — the `WWW-Authenticate` challenge, when the API sent one (an RFC 9470 step-up has no body). */
    val wwwAuthenticate: String? = null,
    /**
     * SSO-4086 — the `Retry-After` header, when the API sent one (a `429 test_identity_rate_limited` carries the seconds
     * to wait; RFC 9110 §10.2.3). Kept as sent; [retryAfterSeconds] reads the delay-seconds form.
     */
    val retryAfter: String? = null,
) : RuntimeException("HTTP $httpStatus: ${errorCode ?: "no_error_code"}${errorDescription?.let { " — $it" } ?: ""}") {

    /** SSO-4086 — `Retry-After` as delay-seconds, when it is one (an HTTP-date form is not parsed: null). */
    val retryAfterSeconds: Long?
        get() = retryAfter?.trim()?.toLongOrNull()?.takeIf { it >= 0 }

    /** True if this is a "you don't have the right scope" failure. */
    val isInsufficientScope: Boolean
        get() = (httpStatus == 403 && !isStepUpRequired) || errorCode == "insufficient_scope"

    /**
     * SSO-3396 — RFC 9470: the operation needs a stronger or fresher sign-in. The `403` carries the
     * challenge in `WWW-Authenticate` (`error="insufficient_user_authentication"`, `acr_values`,
     * `max_age`) and no body.
     */
    val isStepUpRequired: Boolean
        get() = httpStatus == 403 && wwwAuthenticate?.contains("insufficient_user_authentication") == true

    /** The `acr_values` the step-up challenge asks for, when it names them. */
    val stepUpAcrValues: String?
        get() = wwwAuthenticate?.let { Regex("acr_values=\"([^\"]*)\"").find(it)?.groupValues?.get(1) }

    /** The `max_age` (seconds) the step-up challenge asks for, when it names one. */
    val stepUpMaxAge: Long?
        get() = wwwAuthenticate?.let { Regex("max_age=\"?(\\d+)\"?").find(it)?.groupValues?.get(1)?.toLongOrNull() }

    /**
     * SSO-3568 — this request was never sent: the CLI had already told the user their session cannot be
     * renewed. Callers must render [errorDescription] (the sign-in guidance) rather than an HTTP story.
     */
    val isSessionUnrenewable: Boolean
        get() = errorCode == ERROR_CODE_SESSION_UNRENEWABLE

    /**
     * SSO-2413 — the destructive action targets a **production** workspace and no
     * (valid) `X-Thoryn-Confirm` header was sent (product-api's
     * `ProductionConfirmationInterceptor` → `428 production_confirmation_required`).
     * Keyed off the RFC 9457 `errorCode`; the `428` status is a fallback for when
     * the body could not be parsed.
     */
    val isProductionConfirmationRequired: Boolean
        get() = errorCode == ERROR_CODE_CONFIRMATION_REQUIRED || (errorCode == null && httpStatus == 428)

    /**
     * SSO-2413 — an `X-Thoryn-Confirm` header was sent but did not equal the
     * caller's workspace slug (`422 production_confirmation_mismatch`). Keyed off
     * the RFC 9457 `errorCode`; the `422` status is a fallback for an unparsed body.
     */
    val isProductionConfirmationMismatch: Boolean
        get() = errorCode == ERROR_CODE_CONFIRMATION_MISMATCH || (errorCode == null && httpStatus == 422)

    companion object {
        /** RFC 9457 `errorCode` emitted with 428 when a production destructive action lacks the confirm header. */
        const val ERROR_CODE_CONFIRMATION_REQUIRED: String = "production_confirmation_required"

        /** RFC 9457 `errorCode` emitted with 422 when the confirm header does not match the workspace slug. */
        const val ERROR_CODE_CONFIRMATION_MISMATCH: String = "production_confirmation_mismatch"

        /**
         * SSO-3568 — CLIENT-SIDE ONLY: no server ever sends this. It marks a request the CLI refused to
         * send because this process had already reported the sign-in session as unrenewable.
         */
        const val ERROR_CODE_SESSION_UNRENEWABLE: String = "session_cannot_be_renewed"

        /** SSO-3568 — the refusal above, carrying the sign-in guidance as its description. */
        fun sessionUnrenewable(guidance: String): ProductApiException =
            ProductApiException(401, ERROR_CODE_SESSION_UNRENEWABLE, guidance, "")

        fun fromResponse(status: Int, body: String, mapper: ObjectMapper, wwwAuthenticate: String? = null, retryAfter: String? = null): ProductApiException {
            val (code, description) = parseOAuthError(body, mapper)
            return ProductApiException(status, code, description, body, wwwAuthenticate, retryAfter)
        }

        private fun parseOAuthError(body: String, mapper: ObjectMapper): Pair<String?, String?> {
            if (body.isBlank()) return null to null
            return try {
                val parsed: Map<String, Any?> = mapper.readValue(body)
                // Machine code, in precedence order:
                //  - `error`     — RFC 6749 §5.2 (hub token / device endpoints).
                //  - `errorCode` — RFC 9457 extension product-api's ProblemDetailsWriter
                //                  emits across the whole customer plane (SSO-1122). This
                //                  is what `/api/v1/applications`, `/federation-members`,
                //                  `/audit/[*]` return; without it a 404/409 problem body
                //                  loses its stable code and renders as bare "HTTP 404".
                val code = (parsed["error"] as? String)
                    ?: (parsed["errorCode"] as? String)
                val description = (parsed["error_description"] as? String)
                    ?: (parsed["detail"] as? String) // RFC 9457 human-readable detail
                    ?: (parsed["message"] as? String)
                    ?: (parsed["title"] as? String) // RFC 9457 title fallback
                code to description
            } catch (_: Exception) {
                null to null
            }
        }
    }
}
