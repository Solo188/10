package com.adblocker.filter.parser

import com.adblocker.filter.rules.FilterRule
import com.adblocker.filter.rules.RuleOption
import com.adblocker.utils.Logger
import java.io.BufferedReader
import java.io.InputStream
import java.io.InputStreamReader

/**
 * filter.parser — EasyListParser
 *
 * Parses Adblock Plus / EasyList / uBlock Origin compatible filter list syntax.
 *
 * Handles:
 *   ! comments
 *   ## cosmetic rules (element hiding)
 *   #@# cosmetic exceptions
 *   ||domain^ domain-anchored network rules
 *   @@exception whitelist rules
 *   /regex/ raw regex rules (skipped in this implementation — too slow on Android)
 *   plain URL substring rules
 *   $option,option network rule options
 *
 * Returns a lazy sequence so rules are processed on-demand without loading the
 * entire list into memory first.
 */
object EasyListParser {

    private const val TAG = "EasyListParser"

    fun parse(stream: InputStream): Sequence<FilterRule> = sequence {
        val reader = BufferedReader(InputStreamReader(stream, Charsets.UTF_8))
        var lineNumber = 0
        reader.useLines { lines ->
            for (line in lines) {
                lineNumber++
                val trimmed = line.trim()
                if (trimmed.isEmpty()) continue
                try {
                    val rule = parseLine(trimmed)
                    if (rule != null && rule !is FilterRule.Comment) yield(rule)
                } catch (e: Exception) {
                    Logger.d(TAG, "Parse error on line $lineNumber: ${e.message}")
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    //  Line parsing
    // -------------------------------------------------------------------------

    private fun parseLine(line: String): FilterRule? {
        return when {
            line.startsWith("!")        -> FilterRule.Comment
            line.startsWith("[")        -> FilterRule.Comment   // [Adblock Plus 2.0]
            line.startsWith("##")       -> parseCosmeticRule(line, emptyList(), isException = false)
            line.startsWith("#@#")      -> parseCosmeticRule(line, emptyList(), isException = true)
            line.contains("##")        -> parseDomainCosmeticRule(line, isException = false)
            line.contains("#@#")       -> parseDomainCosmeticRule(line, isException = true)
            line.startsWith("@@")       -> parseNetworkRule(line.substring(2), isException = true)
            line.startsWith("/") && line.endsWith("/") -> null  // skip regex — too expensive
            else                        -> parseNetworkRule(line, isException = false)
        }
    }

    // -------------------------------------------------------------------------
    //  Network rules
    // -------------------------------------------------------------------------

    private fun parseNetworkRule(raw: String, isException: Boolean): FilterRule? {
        if (raw.isBlank()) return null

        // Split options from pattern
        val dollarIdx = raw.lastIndexOf('$')
        val (pattern, optionsStr) = if (dollarIdx > 0 && dollarIdx < raw.length - 1) {
            raw.substring(0, dollarIdx) to raw.substring(dollarIdx + 1)
        } else {
            raw to ""
        }

        val options = parseOptions(optionsStr)

        // Domain-anchored rule (||example.com^)
        if (pattern.startsWith("||")) {
            val domain = pattern.substring(2).trimEnd('^', '/', '*')
            if (domain.isNotBlank()) {
                return FilterRule.NetworkRule(
                    pattern = domain,
                    isException = isException,
                    domainAnchored = true,
                    options = options
                )
            }
        }

        // Pure domain rule: |http://example.com or just example.com
        val cleaned = pattern.trimStart('|').trimEnd('^')
        if (cleaned.isNotBlank()) {
            return FilterRule.NetworkRule(
                pattern = cleaned,
                isException = isException,
                domainAnchored = false,
                options = options
            )
        }

        return null
    }

    private fun parseOptions(optionsStr: String): Set<RuleOption> {
        if (optionsStr.isBlank()) return emptySet()
        return optionsStr.split(',').mapNotNull { opt ->
            when (opt.trim().lowercase().trimStart('~')) {
                "third-party"    -> RuleOption.THIRD_PARTY
                "first-party"    -> RuleOption.FIRST_PARTY
                "script"         -> RuleOption.SCRIPT
                "stylesheet"     -> RuleOption.STYLESHEET
                "image"          -> RuleOption.IMAGE
                "xmlhttprequest" -> RuleOption.XMLHTTPREQUEST
                "document"       -> RuleOption.DOCUMENT
                "subdocument"    -> RuleOption.SUBDOCUMENT
                "popup"          -> RuleOption.POPUP
                "ping"           -> RuleOption.PING
                "font"           -> RuleOption.FONT
                "media"          -> RuleOption.MEDIA
                "websocket"      -> RuleOption.WEBSOCKET
                else             -> null
            }
        }.toSet()
    }

    // -------------------------------------------------------------------------
    //  Cosmetic rules
    // -------------------------------------------------------------------------

    private fun parseCosmeticRule(
        line: String,
        domains: List<String>,
        isException: Boolean
    ): FilterRule {
        val sep = if (isException) "#@#" else "##"
        val cssSelector = line.substringAfter(sep)
        return FilterRule.CosmeticRule(
            domains = domains,
            cssSelector = cssSelector,
            isException = isException
        )
    }

    private fun parseDomainCosmeticRule(line: String, isException: Boolean): FilterRule? {
        val sep = if (isException) "#@#" else "##"
        val sepIdx = line.indexOf(sep)
        if (sepIdx < 0) return null
        val domainPart = line.substring(0, sepIdx)
        val domains = domainPart.split(',').map { it.trim() }.filter { it.isNotBlank() }
        val cssSelector = line.substring(sepIdx + sep.length)
        return FilterRule.CosmeticRule(
            domains = domains,
            cssSelector = cssSelector,
            isException = isException
        )
    }
}
