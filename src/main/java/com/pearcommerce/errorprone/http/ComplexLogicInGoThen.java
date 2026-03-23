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
import javax.lang.model.type.TypeMirror;

/**
 * Detects complex processing logic inside {@code JurlProxyFallback.goThen()} lambdas.
 *
 * <p>Logic errors in goThen() trigger retries with all proxy types, wasting proxy credits.
 * Only JSON parsing and basic response validation belong in goThen().
 *
 * <p><b>Flags:</b> for-loops, stream.collect(), complex stream chains (>5 ops), many statements (>5), deep nesting (>2)
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
 * List<Store> stores = new JurlProxyFallback(...)
 *     .goThen(jurl -> jurl.getResponseJsonList(Store.class))
 *     .get();
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

        // Count top-level statements only (don't sum nested blocks)
        int topLevelStatements = 0;
        Tree body = lambda.getBody();
        if (body instanceof BlockTree) {
            topLevelStatements = ((BlockTree) body).getStatements().size();
        }

        ComplexityScanner scanner = new ComplexityScanner(state, topLevelStatements);
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
        if (scanner.streamOpCount > 5) {
            if (!first) msg.append(", ");
            msg.append(scanner.streamOpCount).append(" stream operations (>5)");
            first = false;
        }
        if (scanner.statementCount > 5) {
            if (!first) msg.append(", ");
            msg.append(scanner.statementCount).append(" statements (>5)");
            first = false;
        }
        if (scanner.hasNestedConditional) {
            if (!first) msg.append(", ");
            msg.append("deeply nested conditionals (>2)");
        }

        return msg.toString();
    }

    /** Scans lambda body for patterns indicating business logic vs simple parsing. */
    private static class ComplexityScanner extends TreeScanner<Void, Void> {
        private static final java.util.Set<String> STREAM_INTERMEDIATE_OPS = java.util.Set.of(
            "map", "flatMap", "filter", "peek", "distinct", "sorted", "limit", "skip"
        );

        private final VisitorState state;
        private final int statementCount;

        boolean hasForLoop = false;
        boolean hasStreamCollect = false;
        boolean hasNestedConditional = false;
        int conditionalDepth = 0;
        int streamOpCount = 0;

        ComplexityScanner(VisitorState state, int statementCount) {
            this.state = state;
            this.statementCount = statementCount;
        }

        boolean hasComplexLogic() {
            return hasForLoop || hasStreamCollect || statementCount > 5 || hasNestedConditional || streamOpCount > 5;
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
            Element symbol = ASTHelpers.getSymbol(node);
            if (symbol == null) {
                return super.visitMethodInvocation(node, unused);
            }

            String methodName = symbol.getSimpleName().toString();
            ExpressionTree receiver = ASTHelpers.getReceiver(node);

            if (receiver != null) {
                TypeMirror receiverType = ASTHelpers.getType(receiver);
                if (receiverType != null) {
                    String typeName = receiverType.toString();
                    // Match java.util.stream.Stream and its specializations (IntStream, LongStream, etc.)
                    if (typeName.startsWith("java.util.stream.")) {
                        if ("collect".equals(methodName)) {
                            hasStreamCollect = true;
                        } else if (STREAM_INTERMEDIATE_OPS.contains(methodName)) {
                            streamOpCount++;
                        }
                    }
                }
            }
            return super.visitMethodInvocation(node, unused);
        }

        @Override
        public Void visitIf(IfTree node, Void unused) {
            conditionalDepth++;
            if (conditionalDepth > 2) {
                hasNestedConditional = true;
            }
            Void result = super.visitIf(node, unused);
            conditionalDepth--;
            return result;
        }
    }
}
