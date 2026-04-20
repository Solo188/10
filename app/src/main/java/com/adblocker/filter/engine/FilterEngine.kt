package com.adblocker.filter.engine

import android.content.Context
import com.adblocker.filter.parser.EasyListParser
import com.adblocker.filter.rules.FilterRule
import com.adblocker.utils.Logger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * filter.engine — FilterEngine
 *
 * High-performance URL matching engine built on a domain Trie plus a linear
 * substring list for non-anchored patterns.
 *
 * Data structures:
 *   - domainTrie:     O(k) lookup for ||domain^ rules (k = domain length)
 *   - exceptionTrie:  O(k) lookup for @@whitelist rules
 *   - substringRules: O(n*k) fallback for non-anchored patterns (kept small)
 *
 * Lookup priority:
 *   1. Exception (whitelist) match → PASS
 *   2. Domain Trie match → BLOCK
 *   3. Substring scan → BLOCK
 *   4. Default → PASS
 */
class FilterEngine(private val context: Context) {

    companion object {
        private const val TAG = "FilterEngine"
        // Bundled EasyList asset path
        private const val EASYLIST_ASSET = "filters/easylist.txt"
        private const val EASYPRIVACY_ASSET = "filters/easyprivacy.txt"
    }

    private val domainTrie = DomainTrie()
    private val exceptionTrie = DomainTrie()
    private val substringRules = mutableListOf<String>()

    @Volatile var ruleCount: Int = 0
        private set

    // -------------------------------------------------------------------------
    //  Initialisation (called once at app startup)
    // -------------------------------------------------------------------------

    suspend fun initialize() = withContext(Dispatchers.IO) {
        loadAssetList(EASYLIST_ASSET)
        tryLoadAsset(EASYPRIVACY_ASSET)
        ruleCount = domainTrie.size + substringRules.size
        Logger.i(TAG, "Engine ready: ${domainTrie.size} domain rules, ${substringRules.size} substring rules")
    }

    private fun loadAssetList(assetPath: String) {
        context.assets.open(assetPath).use { stream ->
            EasyListParser.parse(stream).forEach { rule ->
                addRule(rule)
            }
        }
    }

    private fun tryLoadAsset(assetPath: String) {
        try {
            loadAssetList(assetPath)
        } catch (_: Exception) {
            Logger.d(TAG, "Optional asset not found: $assetPath")
        }
    }

    private fun addRule(rule: FilterRule) {
        when (rule) {
            is FilterRule.NetworkRule -> {
                val trie = if (rule.isException) exceptionTrie else domainTrie
                if (rule.domainAnchored) {
                    trie.insert(rule.pattern)
                } else {
                    if (!rule.isException) substringRules.add(rule.pattern)
                }
            }
            is FilterRule.DomainRule -> {
                if (rule.isException) exceptionTrie.insert(rule.domain)
                else domainTrie.insert(rule.domain)
            }
            is FilterRule.CosmeticRule -> { /* stored separately for future CSS injection */ }
            is FilterRule.Comment -> { /* no-op */ }
        }
    }

    // -------------------------------------------------------------------------
    //  Blocking decision
    // -------------------------------------------------------------------------

    /**
     * Decide whether [url] to [host] should be blocked.
     * Thread-safe: all data structures are populated once at init and
     * read-only thereafter.
     */
    fun shouldBlock(url: String, host: String): Boolean {
        val normHost = host.lowercase().removePrefix("www.")

        // Step 1: whitelist check
        if (exceptionTrie.matches(normHost)) return false
        if (url.let { u -> substringRules.any { r -> exceptionTrie.matches(r) && u.contains(r) } }) return false

        // Step 2: domain trie
        if (domainTrie.matches(normHost)) return true

        // Step 3: substring scan (non-anchored rules)
        val urlLower = url.lowercase()
        if (substringRules.any { urlLower.contains(it) }) return true

        return false
    }
}
