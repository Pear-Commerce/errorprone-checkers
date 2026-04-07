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
import com.sun.source.util.TreePath;
import com.sun.source.util.TreeScanner;

import com.sun.tools.javac.code.Type;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.lang.model.element.Element;

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
 *
 * <p><b>When to suppress:</b> Not all cookies scope the response. Authentication tokens, CSRF
 * cookies, and analytics/tracking cookies do not affect the returned data — all callers receive
 * the same response regardless of their cookie value. In those cases, sharing a single cache entry
 * is correct and {@code extraCacheKey} is not needed. Suppress this warning with
 * {@code @SuppressWarnings("JurlCacheWithCookieMissingExtraCacheKey")} and a comment explaining
 * why the cookie does not scope the response.
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

    private static final String JURL_PROXY_FALLBACK_CLASS = "com.pear.http.JurlProxyFallback";

    @Override
    public Description matchMethodInvocation(MethodInvocationTree tree, VisitorState state) {
        if (!USE_JURL_CACHE.matches(tree, state)) {
            return Description.NO_MATCH;
        }

        // Only care about useJurlCache(true, ...) — caching disabled is fine
        if (!isCachingEnabled(tree, state)) {
            return Description.NO_MATCH;
        }

        // Walk DOWN the receiver chain (calls before useJurlCache) to find the constructor
        NewClassTree constructor = null;
        ExpressionTree node = tree;
        while (node instanceof MethodInvocationTree mit) {
            ExpressionTree receiver = getReceiver(mit);
            if (receiver instanceof NewClassTree nct) {
                constructor = nct;
                break;
            }
            node = receiver;
        }

        if (constructor == null) {
            return Description.NO_MATCH;
        }

        // Walk UP the call chain (calls after useJurlCache) via TreePath to find extraCacheKey
        if (hasExtraCacheKeyAbove(state)) {
            return Description.NO_MATCH;
        }

        // Check whether the supplier lambda argument to the constructor calls .cookie() on a LoggedJurl
        if (!supplierHasCookie(constructor, state)) {
            return Description.NO_MATCH;
        }

        return describeMatch(tree);
    }

    /**
     * Walks up the TreePath to check if any enclosing method invocation in the same chain
     * calls extraCacheKey on JurlProxyFallback.
     *
     * <p>In a fluent chain {@code useJurlCache(...).extraCacheKey(...)}, the AST parent of the
     * {@code useJurlCache} MethodInvocationTree is the MemberSelectTree for {@code .extraCacheKey},
     * not the outer MethodInvocationTree. We must handle both node types when walking up.
     */
    private boolean hasExtraCacheKeyAbove(VisitorState state) {
        TreePath path = state.getPath().getParentPath();
        while (path != null) {
            Tree leaf = path.getLeaf();
            if (leaf instanceof MemberSelectTree mst) {
                // This is the ".methodName" selector — check if it's extraCacheKey
                if ("extraCacheKey".equals(mst.getIdentifier().toString())) {
                    return true;
                }
                path = path.getParentPath();
            } else if (leaf instanceof MethodInvocationTree mit) {
                // Stop if we've left the JurlProxyFallback chain
                Type jurlType = state.getTypeFromString(JURL_PROXY_FALLBACK_CLASS);
                Type mitType = ASTHelpers.getType(mit);
                if (mitType == null || jurlType == null ||
                    !ASTHelpers.isSameType(mitType, jurlType, state)) {
                    break;
                }
                path = path.getParentPath();
            } else {
                break;
            }
        }
        return false;
    }

    /**
     * Scans only the supplier lambda argument (the last functional-interface argument) of the
     * JurlProxyFallback constructor for .cookie() calls on a LoggedJurl receiver.
     */
    private boolean supplierHasCookie(NewClassTree constructor, VisitorState state) {
        Type loggedJurlType = state.getTypeFromString("com.pear.http.LoggedJurl");
        if (loggedJurlType == null) {
            return false;
        }

        // Find the supplier lambda — the last argument that is a lambda or method reference
        LambdaExpressionTree supplierLambda = null;
        for (ExpressionTree arg : constructor.getArguments()) {
            if (arg instanceof LambdaExpressionTree lambda) {
                supplierLambda = lambda;
            }
        }

        if (supplierLambda == null) {
            return false;
        }

        AtomicBoolean found = new AtomicBoolean(false);
        final LambdaExpressionTree lambdaToScan = supplierLambda;
        new TreeScanner<Void, Void>() {
            @Override
            public Void visitMethodInvocation(MethodInvocationTree node, Void unused) {
                if (!found.get() && "cookie".equals(getMethodName(node))) {
                    ExpressionTree receiver = getReceiver(node);
                    if (receiver != null && isLoggedJurlChain(receiver, loggedJurlType, state)) {
                        found.set(true);
                    }
                }
                return super.visitMethodInvocation(node, unused);
            }
        }.scan(lambdaToScan, null);
        return found.get();
    }

    private boolean isLoggedJurlChain(ExpressionTree expr, Type loggedJurlType, VisitorState state) {
        ExpressionTree current = expr;
        while (current != null) {
            Type type = ASTHelpers.getType(current);
            if (type != null &&
                (ASTHelpers.isSameType(type, loggedJurlType, state) ||
                 ASTHelpers.isSubtype(type, loggedJurlType, state))) {
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

    private boolean isCachingEnabled(MethodInvocationTree tree, VisitorState state) {
        if (tree.getArguments().isEmpty()) return false;
        Object constantValue = ASTHelpers.constValue(tree.getArguments().get(0));
        return Boolean.TRUE.equals(constantValue);
    }

    private static String getMethodName(MethodInvocationTree tree) {
        Element sym = ASTHelpers.getSymbol(tree);
        if (sym != null) return sym.getSimpleName().toString();
        if (tree.getMethodSelect() instanceof MemberSelectTree mst) {
            return mst.getIdentifier().toString();
        }
        String s = tree.getMethodSelect().toString();
        int dot = s.lastIndexOf('.');
        return dot >= 0 ? s.substring(dot + 1) : s;
    }

    private static ExpressionTree getReceiver(MethodInvocationTree tree) {
        return unwrap(ASTHelpers.getReceiver(tree));
    }

    /** Strip parens/casts that can appear in chains so we don't miss constructors or receivers. */
    private static ExpressionTree unwrap(ExpressionTree e) {
        if (e == null) return null;
        ExpressionTree cur = e;
        boolean changed;
        do {
            changed = false;
            if (cur instanceof ParenthesizedTree p) {
                cur = p.getExpression();
                changed = true;
            } else if (cur instanceof TypeCastTree t) {
                cur = t.getExpression();
                changed = true;
            }
        } while (changed);
        return cur;
    }
}
