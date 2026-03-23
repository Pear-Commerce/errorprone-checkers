package com.pearcommerce.errorprone.http;

import static com.google.errorprone.matchers.Matchers.instanceMethod;

import com.google.auto.service.AutoService;
import com.google.errorprone.BugPattern;
import com.google.errorprone.BugPattern.SeverityLevel;
import com.google.errorprone.VisitorState;
import com.google.errorprone.bugpatterns.BugChecker;
import com.google.errorprone.matchers.Description;
import com.google.errorprone.matchers.Matcher;
import com.sun.source.tree.*;
import com.sun.source.util.TreeScanner;

/**
 * Detects complex processing logic inside {@code JurlProxyFallback.goThen()} lambdas.
 *
 * <p>Logic errors in goThen() trigger retries with all proxy types, wasting proxy credits.
 * Only JSON parsing and basic response validation belong in goThen().
 *
 * <p><b>Flags:</b> for-loops, stream.collect(), multiple statements, nested conditionals
 *
 * <p><b>Example:</b>
 * <pre>{@code
 * // BAD: Processing in goThen wastes proxies on NPE
 * .goThen(jurl -> {
 *     List<Store> stores = jurl.getResponseJsonList(Store.class);
 *     Map<String, Store> map = new HashMap<>();
 *     for (Store s : stores) { map.put(s.id, s); }  // ← Flagged
 *     return map;
 * });
 *
 * // GOOD: Only parsing in goThen
 * List<Store> stores = .goThen(jurl -> jurl.getResponseJsonList(Store.class)).get();
 * Map<String, Store> map = new HashMap<>();
 * for (Store s : stores) { map.put(s.id, s); }  // Processing outside - OK
 * }</pre>
 */
@AutoService(BugChecker.class)
@BugPattern(
    name = "ComplexLogicInGoThen",
    summary = "Complex processing in JurlProxyFallback.goThen() wastes proxy credits on logic errors",
    severity = SeverityLevel.WARNING
)
public final class ComplexLogicInGoThen extends BugChecker
    implements BugChecker.MethodInvocationTreeMatcher {

    private static final Matcher<ExpressionTree> GO_THEN =
        instanceMethod().onExactClass("com.pear.http.JurlProxyFallback").named("goThen");

    @Override
    public Description matchMethodInvocation(MethodInvocationTree tree, VisitorState state) {
        if (!GO_THEN.matches(tree, state)) {
            return Description.NO_MATCH;
        }

        if (tree.getArguments().isEmpty()) {
            return Description.NO_MATCH;
        }

        ExpressionTree arg = tree.getArguments().get(0);
        if (!(arg instanceof LambdaExpressionTree)) {
            return Description.NO_MATCH;
        }

        LambdaExpressionTree lambda = (LambdaExpressionTree) arg;
        ComplexityScanner scanner = new ComplexityScanner();
        lambda.getBody().accept(scanner, null);

        if (scanner.hasComplexLogic()) {
            return buildDescription(tree)
                .setMessage(buildMessage(scanner))
                .build();
        }

        return Description.NO_MATCH;
    }

    private String buildMessage(ComplexityScanner scanner) {
        StringBuilder msg = new StringBuilder(
            "Complex processing in goThen() wastes proxy credits. Move logic outside. Found: "
        );

        boolean first = true;
        if (scanner.hasForLoop) {
            msg.append("for-loop");
            first = false;
        }
        if (scanner.hasStreamCollect) {
            if (!first) msg.append(", ");
            msg.append("stream.collect()");
            first = false;
        }
        if (scanner.statementCount > 3) {
            if (!first) msg.append(", ");
            msg.append(scanner.statementCount).append(" statements (>3)");
            first = false;
        }
        if (scanner.hasNestedConditional) {
            if (!first) msg.append(", ");
            msg.append("nested conditionals");
        }

        return msg.toString();
    }

    /** Scans lambda body for patterns indicating business logic vs simple parsing. */
    private static class ComplexityScanner extends TreeScanner<Void, Void> {
        boolean hasForLoop = false;
        boolean hasStreamCollect = false;
        boolean hasNestedConditional = false;
        int statementCount = 0;
        int conditionalDepth = 0;

        boolean hasComplexLogic() {
            return hasForLoop || hasStreamCollect || statementCount > 3 || hasNestedConditional;
        }

        @Override
        public Void visitForLoop(ForLoopTree node, Void unused) {
            hasForLoop = true;
            return super.visitForLoop(node, unused);
        }

        @Override
        public Void visitEnhancedForLoop(EnhancedForLoopTree node, Void unused) {
            hasForLoop = true;
            return super.visitEnhancedForLoop(node, unused);
        }

        @Override
        public Void visitMethodInvocation(MethodInvocationTree node, Void unused) {
            String methodString = node.getMethodSelect().toString();
            if (methodString.endsWith(".collect") || methodString.contains(".collect(")) {
                hasStreamCollect = true;
            }
            return super.visitMethodInvocation(node, unused);
        }

        @Override
        public Void visitBlock(BlockTree node, Void unused) {
            statementCount += node.getStatements().size();
            return super.visitBlock(node, unused);
        }

        @Override
        public Void visitIf(IfTree node, Void unused) {
            conditionalDepth++;
            if (conditionalDepth > 1) {
                hasNestedConditional = true;
            }
            Void result = super.visitIf(node, unused);
            conditionalDepth--;
            return result;
        }
    }
}
