package com.pearcommerce.errorprone.http;

import static com.google.errorprone.matchers.Matchers.instanceMethod;

import com.google.auto.service.AutoService;
import com.google.errorprone.BugPattern;
import com.google.errorprone.BugPattern.SeverityLevel;
import com.google.errorprone.VisitorState;
import com.google.errorprone.bugpatterns.BugChecker;
import com.google.errorprone.matchers.Description;
import com.google.errorprone.matchers.Matcher;
import com.google.errorprone.util.ASTHelpers;
import com.sun.source.tree.*;
import com.sun.source.util.TreeScanner;

import javax.lang.model.type.TypeMirror;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Flags {@code JurlProxyFallback} chains that call {@code .useJurlCache(true, ...)} without
 * {@code .extraCacheKey(...)} when the Jurl supplier lambda calls {@code .cookie(...)}.
 *
 * <p>The Jurl cache key is built from the URL and request body only — cookies are never included.
 * When a cookie scopes the request to a specific store or location (e.g. {@code wfm_store_d8}),
 * all callers share a single cache entry and receive one location's data.
 *
 * <p><b>Example:</b>
 * <pre>{@code
 * // BAD: all stores share one cache entry keyed only on the URL
 * new JurlProxyFallback(..., () -> new LoggedJurl()
 *         .cookie("wfm_store_d8", storeCookie)
 *         .url(url))
 *     .useJurlCache(true, TimeUnit.HOURS.toMillis(20))  // ← Flagged
 *     .goThen(...);
 *
 * // GOOD: each store gets its own cache entry
 * new JurlProxyFallback(..., () -> new LoggedJurl()
 *         .cookie("wfm_store_d8", storeCookie)
 *         .url(url))
 *     .useJurlCache(true, TimeUnit.HOURS.toMillis(20))
 *     .extraCacheKey(storeId)                           // ← Required
 *     .goThen(...);
 * }</pre>
 */
@AutoService(BugChecker.class)
@BugPattern(
    name = "JurlCacheWithCookieMissingExtraCacheKey",
    summary = "JurlProxyFallback uses cache with cookies but no extraCacheKey — all callers share one cache entry",
    severity = SeverityLevel.WARNING
)
public final class JurlCacheWithCookieMissingExtraCacheKey extends BugChecker
    implements BugChecker.MethodInvocationTreeMatcher {

    private static final Matcher<ExpressionTree> USE_JURL_CACHE =
        instanceMethod().onExactClass("com.pear.http.JurlProxyFallback").named("useJurlCache");

    @Override
    public Description matchMethodInvocation(MethodInvocationTree tree, VisitorState state) {
        if (!USE_JURL_CACHE.matches(tree, state)) {
            return Description.NO_MATCH;
        }

        // Only care about useJurlCache(true, ...) — caching disabled is fine
        if (!isCachingEnabled(tree)) {
            return Description.NO_MATCH;
        }

        // Walk the JurlProxyFallback chain to find extraCacheKey and the constructor
        boolean hasExtraCacheKey = false;
        NewClassTree constructor = null;

        ExpressionTree node = tree;
        while (node instanceof MethodInvocationTree mit) {
            String name = getMethodName(mit);
            if ("extraCacheKey".equals(name)) {
                hasExtraCacheKey = true;
            }
            ExpressionTree receiver = getReceiver(mit);
            if (receiver instanceof NewClassTree nct) {
                constructor = nct;
                break;
            }
            node = receiver;
        }

        if (hasExtraCacheKey || constructor == null) {
            return Description.NO_MATCH;
        }

        // Check whether any argument to the constructor contains a .cookie() call on a LoggedJurl
        if (!constructorHasCookieInSupplier(constructor, state)) {
            return Description.NO_MATCH;
        }

        return describeMatch(tree);
    }

    private boolean constructorHasCookieInSupplier(NewClassTree constructor, VisitorState state) {
        AtomicBoolean found = new AtomicBoolean(false);
        new TreeScanner<Void, Void>() {
            @Override
            public Void visitMethodInvocation(MethodInvocationTree node, Void unused) {
                if (!found.get() && "cookie".equals(getMethodName(node))) {
                    // Verify the receiver is a LoggedJurl (or its chain)
                    ExpressionTree receiver = getReceiver(node);
                    if (receiver != null && isLoggedJurlChain(receiver, state)) {
                        found.set(true);
                    }
                }
                return super.visitMethodInvocation(node, unused);
            }
        }.scan(constructor, null);
        return found.get();
    }

    private boolean isLoggedJurlChain(ExpressionTree expr, VisitorState state) {
        // Walk down the chain to find a LoggedJurl type
        ExpressionTree current = expr;
        while (current != null) {
            TypeMirror type = ASTHelpers.getType(current);
            if (type != null && type.toString().contains("LoggedJurl")) {
                return true;
            }
            if (current instanceof MethodInvocationTree mit) {
                current = getReceiver(mit);
            } else {
                break;
            }
        }
        return false;
    }

    private boolean isCachingEnabled(MethodInvocationTree tree) {
        if (tree.getArguments().isEmpty()) return false;
        return tree.getArguments().get(0).toString().equals("true");
    }

    private String getMethodName(MethodInvocationTree tree) {
        ExpressionTree select = tree.getMethodSelect();
        if (select instanceof MemberSelectTree mst) {
            return mst.getIdentifier().toString();
        }
        return select.toString();
    }

    private ExpressionTree getReceiver(MethodInvocationTree tree) {
        ExpressionTree select = tree.getMethodSelect();
        if (select instanceof MemberSelectTree mst) {
            return mst.getExpression();
        }
        return null;
    }
}
