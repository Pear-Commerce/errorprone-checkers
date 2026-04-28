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

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Flags {@code JurlProxyFallback.goThen()} lambdas that check the HTTP response status or
 * test a deserialized object for null, but return a value instead of throwing on failure.
 *
 * <p>{@code goThen()} is the retry boundary: any exception thrown inside it causes
 * {@code JurlProxyFallback} to retry with the next proxy type (STATIC → ISP → RESIDENTIAL
 * → ZENROWS → SCRAPFLY). Returning a value — including an empty collection or a default
 * object — silently treats a bad response as success. The proxy cycle is never retried,
 * and the incomplete or malformed data propagates silently to callers.
 *
 * <p>This is the complement of {@link ComplexLogicInGoThen}: that checker catches lambdas
 * that accidentally <em>throw</em> on logic errors; this one catches lambdas that
 * accidentally <em>swallow</em> HTTP failures by returning instead of throwing.
 *
 * <p><b>Triggers on exactly two patterns:</b>
 * <ol>
 *   <li>An {@code if} whose condition calls {@code getResponseCode()} and whose then-branch
 *       returns without throwing — the caller never sees the bad status.
 *   <li>An {@code if} that null-checks the result of {@code getResponseJsonObject()},
 *       {@code getResponseJsonList()}, or {@code getResponseJsonMap()} and whose then-branch
 *       returns without throwing — deserialization failure is silenced.
 * </ol>
 *
 * <p>Format-detection checks ({@code responseBodyContains}, HTML scraping, field presence
 * tests unrelated to the HTTP status) are intentionally <em>not</em> flagged — those are
 * business logic, not HTTP validation.
 *
 * <p><b>Example:</b>
 * <pre>{@code
 * // BAD: 4xx returns empty list — no retry, caller sees empty success
 * .goThen(lj -> {
 *     if (lj.getResponseCode() >= 400) {
 *         return new ArrayList<>();              // ← flagged
 *     }
 *     return lj.getResponseJsonList(Item.class);
 * });
 *
 * // BAD: null deserialization result returns empty object — no retry
 * // (flagged only when getResponseJsonObject() is called directly in the if condition)
 * .goThen(lj -> {
 *     if (lj.getResponseJsonObject(KrogerResponse.class) == null) {
 *         return new KrogerResponse();          // ← flagged
 *     }
 *     return lj.getResponseJsonObject(KrogerResponse.class).data;
 * });
 *
 * // GOOD: throw explicitly so JurlProxyFallback retries with the next proxy
 * .goThen(lj -> {
 *     if (lj.getResponseCode() >= 400) {
 *         throw new JurlException(lj, "status " + lj.getResponseCode() + ", retrying");
 *     }
 *     return lj.getResponseJsonList(Item.class);
 * });
 * }</pre>
 */
@AutoService(BugChecker.class)
@BugPattern(
    name = "GoThenValidationWithoutThrow",
    summary = "goThen() checks HTTP status or null-tests a deserialized object but returns " +
              "instead of throwing — the failure is silenced and JurlProxyFallback never retries",
    severity = SeverityLevel.WARNING
)
public final class GoThenValidationWithoutThrow extends BugChecker
    implements BugChecker.MethodInvocationTreeMatcher {

    private static final Matcher<ExpressionTree> GO_THEN =
        instanceMethod().onExactClass("com.pear.http.JurlProxyFallback").named("goThen");

    /**
     * Deserialization methods whose return value being null indicates a response failure
     * worth retrying. Intentionally excludes body-string methods (getResponseBody, toCurl,
     * getDocument, responseBodyContains) — those are used for format detection, not HTTP
     * validation.
     */
    private static final java.util.Set<String> DESERIALIZE_METHODS = java.util.Set.of(
        "getResponseJsonObject", "getResponseJsonList", "getResponseJsonMap"
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
        if (!(body instanceof BlockTree block)) {
            return Description.NO_MATCH;
        }

        ValidationScanner scanner = new ValidationScanner();
        block.accept(scanner, null);

        if (scanner.triggerKind != TriggerKind.NONE) {
            return buildDescription(tree)
                .setMessage(buildMessage(scanner.triggerKind))
                .build();
        }

        return Description.NO_MATCH;
    }

    private static String buildMessage(TriggerKind kind) {
        String specific = switch (kind) {
            case STATUS_CODE ->
                "getResponseCode() is called in the condition but the branch returns instead of " +
                "throwing — the bad status is silenced and no proxy retry occurs";
            case NULL_DESERIALIZE ->
                "getResponseJsonObject/List/Map() is null-checked in the condition but the null " +
                "branch returns instead of throwing — deserialization failure is silenced";
            default -> "response validation branch returns instead of throwing";
        };
        return "goThen() " + specific + ". " +
               "Use 'throw new JurlException(<jurl-param>, \"<reason>\")' so JurlProxyFallback " +
               "retries with the next proxy type (STATIC → ISP → RESIDENTIAL → ZENROWS → SCRAPFLY).";
    }

    private enum TriggerKind { NONE, STATUS_CODE, NULL_DESERIALIZE }

    /**
     * Scans for if-statements matching either trigger pattern. Does not recurse into nested
     * lambdas (they have independent retry semantics).
     */
    private static class ValidationScanner extends TreeScanner<Void, Void> {

        TriggerKind triggerKind = TriggerKind.NONE;

        @Override
        public Void visitLambdaExpression(LambdaExpressionTree node, Void unused) {
            return null;
        }

        @Override
        public Void visitIf(IfTree node, Void unused) {
            if (triggerKind != TriggerKind.NONE) {
                return null; // already found one, stop scanning
            }

            TriggerKind kind = classifyCondition(node.getCondition());
            if (kind != TriggerKind.NONE && thenBranchReturnsWithoutThrowing(node.getThenStatement())) {
                triggerKind = kind;
                return null;
            }

            return super.visitIf(node, unused);
        }

        /**
         * Returns STATUS_CODE if the condition calls getResponseCode(), NULL_DESERIALIZE if
         * it null-checks the result of a deserialization method, NONE otherwise.
         */
        private TriggerKind classifyCondition(ExpressionTree condition) {
            AtomicBoolean hasStatusCode = new AtomicBoolean(false);
            AtomicBoolean hasDeserializeNullCheck = new AtomicBoolean(false);

            new TreeScanner<Void, Void>() {
                @Override
                public Void visitMethodInvocation(MethodInvocationTree node, Void unused) {
                    String name = methodName(node);
                    if ("getResponseCode".equals(name)) {
                        hasStatusCode.set(true);
                    }
                    return super.visitMethodInvocation(node, unused);
                }

                @Override
                public Void visitBinary(BinaryTree node, Void unused) {
                    // Only `expr == null` or `null == expr` — the failure path.
                    // `!= null` guards the success path; the else-branch may throw correctly.
                    if (node.getKind() == Tree.Kind.EQUAL_TO) {
                        ExpressionTree left = node.getLeftOperand();
                        ExpressionTree right = node.getRightOperand();
                        if (isNullLiteral(left) && callsDeserializeMethod(right)) {
                            hasDeserializeNullCheck.set(true);
                        } else if (isNullLiteral(right) && callsDeserializeMethod(left)) {
                            hasDeserializeNullCheck.set(true);
                        }
                    }
                    return super.visitBinary(node, unused);
                }

                // Also detect `if (resp == null)` where resp was assigned from a deserialize call:
                // the variable itself appears on one side and null on the other, but we can't
                // cheaply trace assignments here — only flag the direct-call form to stay precise.
            }.scan(condition, null);

            if (hasStatusCode.get()) return TriggerKind.STATUS_CODE;
            if (hasDeserializeNullCheck.get()) return TriggerKind.NULL_DESERIALIZE;
            return TriggerKind.NONE;
        }

        private boolean isNullLiteral(ExpressionTree expr) {
            return expr.getKind() == Tree.Kind.NULL_LITERAL;
        }

        private boolean callsDeserializeMethod(ExpressionTree expr) {
            AtomicBoolean found = new AtomicBoolean(false);
            new TreeScanner<Void, Void>() {
                @Override
                public Void visitMethodInvocation(MethodInvocationTree node, Void unused) {
                    if (DESERIALIZE_METHODS.contains(methodName(node))) {
                        found.set(true);
                    }
                    return super.visitMethodInvocation(node, unused);
                }
            }.scan(expr, null);
            return found.get();
        }

        /**
         * Returns true if the statement returns without any throw reachable inside it.
         * A block that throws on one path and returns on another is fine — only flag
         * branches that exclusively return.
         */
        private boolean thenBranchReturnsWithoutThrowing(StatementTree then) {
            // Unwrap single-statement block
            StatementTree effective = unwrapBlock(then);
            if (effective instanceof ReturnTree) {
                return true;
            }
            if (then instanceof BlockTree block) {
                return blockEndsWithReturn(block) && !blockContainsThrow(block);
            }
            return false;
        }

        private StatementTree unwrapBlock(StatementTree stmt) {
            if (stmt instanceof BlockTree block && block.getStatements().size() == 1) {
                return block.getStatements().getFirst();
            }
            return stmt;
        }

        private boolean blockEndsWithReturn(BlockTree block) {
            var stmts = block.getStatements();
            return !stmts.isEmpty() && stmts.getLast() instanceof ReturnTree;
        }

        private boolean blockContainsThrow(BlockTree block) {
            AtomicBoolean found = new AtomicBoolean(false);
            new TreeScanner<Void, Void>() {
                @Override
                public Void visitThrow(ThrowTree node, Void unused) {
                    found.set(true);
                    return null;
                }
                @Override
                public Void visitLambdaExpression(LambdaExpressionTree node, Void unused) {
                    return null;
                }
            }.scan(block, null);
            return found.get();
        }

        private static String methodName(MethodInvocationTree tree) {
            ExpressionTree sel = tree.getMethodSelect();
            if (sel instanceof MemberSelectTree mst) return mst.getIdentifier().toString();
            return sel.toString();
        }
    }
}
