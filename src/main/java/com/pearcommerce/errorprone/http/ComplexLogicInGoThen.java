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

import javax.lang.model.element.Element;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.TypeElement;
import java.util.ArrayList;
import java.util.List;

/**
 * Detects application-service calls inside {@code JurlProxyFallback.goThen()} for-loops.
 *
 * <p>{@code goThen()} is the retry boundary: any exception thrown inside it causes
 * {@code JurlProxyFallback} to retry the HTTP request with the next proxy type (STATIC →
 * ISP → RESIDENTIAL → ZENROWS → SCRAPFLY). A for-loop over parsed response data is
 * structurally fine — the real risk is calling application services (database lookups,
 * ORM queries, external HTTP calls) from inside that loop. Those calls can throw for
 * reasons completely unrelated to the HTTP response, exhausting all proxy types on a
 * logic bug instead of a network error.
 *
 * <p>Plain iteration over a parsed response collection — field access, string manipulation,
 * JSoup DOM operations, JSON parsing — is safe and not flagged.
 *
 * <p><b>Flags:</b> for-loops containing calls to application-service methods — identified
 * by their declaring class being in a {@code com.pear.*} package other than the HTTP/lang
 * utility packages ({@code com.pear.http}, {@code com.pear.lang}, {@code com.pear.text},
 * {@code com.pear.concurrency.currency}).
 *
 * <p><b>Example:</b>
 * <pre>{@code
 * // BAD: UPC.fetchFuzzy() is a DB call — throws inside goThen retries all proxies
 * .goThen(lj -> {
 *     MikMakConfig config = JSON.parseObject(lj.getResponseBody(), MikMakConfig.class);
 *     for (MikMakProduct product : config.products) {
 *         UPC upc = UPC.fetchFuzzy(product.ean);   // ← DB call, flagged
 *         ...
 *     }
 *     return results;
 * });
 *
 * // GOOD: parse in goThen, do DB lookups outside the retry boundary
 * MikMakConfig config = new JurlProxyFallback(...)
 *     .goThen(lj -> JSON.parseObject(lj.getResponseBody(), MikMakConfig.class))
 *     .get();
 * for (MikMakProduct product : config.products) {
 *     UPC upc = UPC.fetchFuzzy(product.ean);   // safe here
 *     ...
 * }
 * }</pre>
 */
@AutoService(BugChecker.class)
@BugPattern(
    name = "ComplexLogicInGoThen",
    summary = "Application-service call inside a goThen() for-loop — if it throws, " +
              "JurlProxyFallback retries across all proxy types for a non-network error",
    severity = SeverityLevel.WARNING
)
public final class ComplexLogicInGoThen extends BugChecker
    implements BugChecker.MethodInvocationTreeMatcher {

    private static final Matcher<ExpressionTree> GO_THEN =
        instanceMethod().onExactClass("com.pear.http.JurlProxyFallback").named("goThen");

    /**
     * com.pear.* sub-packages that contain only response/HTTP/text utilities and are safe
     * to call from inside goThen(). Everything else under com.pear.* is application code
     * (ORM, entities, jobs, scrapers) that can throw for non-network reasons.
     */
    private static final java.util.Set<String> SAFE_PEAR_PACKAGES = java.util.Set.of(
        "com.pear.http",
        "com.pear.lang",
        "com.pear.text",
        "com.pear.concurrency.currency"
    );

    @Override
    public Description matchMethodInvocation(MethodInvocationTree tree, VisitorState state) {
        if (!GO_THEN.matches(tree, state)) {
            return Description.NO_MATCH;
        }

        if (tree.getArguments().isEmpty()) {
            return Description.NO_MATCH;
        }

        ExpressionTree arg = tree.getArguments().getFirst();
        if (!(arg instanceof LambdaExpressionTree lambda)) {
            return Description.NO_MATCH;
        }

        Tree body = lambda.getBody();
        if (!(body instanceof BlockTree)) {
            return Description.NO_MATCH;
        }

        AppServiceCallInLoopScanner scanner = new AppServiceCallInLoopScanner(state);
        lambda.getBody().accept(scanner, null);

        if (!scanner.violations.isEmpty()) {
            String calls = String.join(", ", scanner.violations);
            return buildDescription(tree)
                .setMessage(
                    "goThen() for-loop calls application service(s): " + calls + ". " +
                    "If any of these throw, JurlProxyFallback retries across all proxy types " +
                    "(STATIC → ISP → RESIDENTIAL → ZENROWS → SCRAPFLY) for a non-network error. " +
                    "Move the loop outside goThen() — parse the response inside, process outside."
                )
                .build();
        }

        return Description.NO_MATCH;
    }

    /**
     * Scans lambda body for for-loops that contain application-service method calls.
     * Does not recurse into nested lambdas.
     */
    private static class AppServiceCallInLoopScanner extends TreeScanner<Void, Void> {

        private final VisitorState state;
        private boolean insideLoop = false;
        final List<String> violations = new ArrayList<>();

        AppServiceCallInLoopScanner(VisitorState state) {
            this.state = state;
        }

        @Override
        public Void visitLambdaExpression(LambdaExpressionTree node, Void unused) {
            return null;
        }

        @Override
        public Void visitForLoop(ForLoopTree node, Void unused) {
            boolean wasInLoop = insideLoop;
            insideLoop = true;
            super.visitForLoop(node, unused);
            insideLoop = wasInLoop;
            return null;
        }

        @Override
        public Void visitEnhancedForLoop(EnhancedForLoopTree node, Void unused) {
            boolean wasInLoop = insideLoop;
            insideLoop = true;
            super.visitEnhancedForLoop(node, unused);
            insideLoop = wasInLoop;
            return null;
        }

        @Override
        public Void visitMethodInvocation(MethodInvocationTree node, Void unused) {
            if (insideLoop) {
                Element sym = ASTHelpers.getSymbol(node);
                if (sym instanceof ExecutableElement exec) {
                    TypeElement enclosing = (TypeElement) exec.getEnclosingElement();
                    String className = enclosing.getQualifiedName().toString();
                    if (isApplicationServiceClass(className)) {
                        String methodName = exec.getSimpleName().toString();
                        String violation = className.substring(className.lastIndexOf('.') + 1) + "." + methodName + "()";
                        if (!violations.contains(violation)) {
                            violations.add(violation);
                        }
                    }
                }
            }
            return super.visitMethodInvocation(node, unused);
        }

        private boolean isApplicationServiceClass(String qualifiedClassName) {
            if (!qualifiedClassName.startsWith("com.pear.")) {
                return false;
            }
            for (String safe : SAFE_PEAR_PACKAGES) {
                if (qualifiedClassName.startsWith(safe + ".") || qualifiedClassName.equals(safe)) {
                    return false;
                }
            }
            return true;
        }
    }
}
