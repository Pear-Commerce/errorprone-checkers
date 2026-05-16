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
 * Flags cached {@code JurlProxyFallback.goThen()} lambdas that check a retryable/broad HTTP
 * response status or test a deserialized object for null, but return a cacheable value instead
 * of throwing on failure.
 *
 * <p>{@code goThen()} is the retry boundary: any exception thrown inside it causes
 * {@code JurlProxyFallback} to retry with the next proxy type (STATIC → ISP → RESIDENTIAL
 * → ZENROWS → SCRAPFLY). When {@code useJurlCache(true, ...)} is enabled, returning a value —
 * including an empty collection or a default object — silently treats a bad response as success
 * and can cache an incomplete or malformed value for future callers, causing wrong behavior
 * that is difficult to debug and fix.
 *
 * <p>This is the complement of {@link GoThenRiskyRetry}: that checker catches lambdas
 * that accidentally <em>throw</em> on logic errors; this one catches lambdas that
 * accidentally <em>swallow</em> HTTP failures by returning instead of throwing.
 *
 * <p><b>Triggers on exactly two patterns:</b>
 * <ol>
 *   <li>An {@code if} whose condition calls {@code getResponseCode()} for a broad non-success or
 *       5xx path and whose then-branch returns without throwing — the cache stores the bad result.
 *   <li>An {@code if} that null-checks the result of {@code getResponseJsonObject()},
 *       {@code getResponseJsonList()}, or {@code getResponseJsonMap()} and whose then-branch
 *       returns without throwing — the cache stores the bad result.
 * </ol>
 *
 * <p>Format-detection checks ({@code responseBodyContains}, HTML scraping, field presence
 * tests unrelated to the HTTP status), plus exact/bounded 4xx no-data checks, are intentionally
 * <em>not</em> flagged — those are business logic, not HTTP validation.
 *
 * <p><b>Example:</b>
 * <pre>{@code
 * // BAD: broad error path returns empty list — no retry for 5xx, cache sees empty success
 * .useJurlCache(true, TimeUnit.DAYS.toMillis(1))
 * .goThen(lj -> {
 *     if (lj.getResponseCode() >= 400) {
 *         return new ArrayList<>();              // ← flagged
 *     }
 *     return lj.getResponseJsonList(Item.class);
 * });
 *
 * // BAD: null deserialization result returns empty object — no retry
 * // (flagged only when getResponseJsonObject() is called directly in the if condition)
 * .useJurlCache(true, TimeUnit.DAYS.toMillis(1))
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
    name = "GoThenRiskyCaching",
    summary = "cached goThen() returns instead of throwing on a failed request; the wrong value " +
              "can be cached and cause hard-to-debug behavior",
    severity = SeverityLevel.WARNING
)
public final class GoThenRiskyCaching extends BugChecker
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
        if (!hasEnabledJurlCacheInChain(tree)) {
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

    private static boolean hasEnabledJurlCacheInChain(MethodInvocationTree tree) {
        ExpressionTree receiver = receiver(tree);
        while (receiver != null) {
            receiver = stripParens(receiver);
            if (receiver instanceof MethodInvocationTree invocation) {
                if ("useJurlCache".equals(methodName(invocation)) && cacheCanBeEnabled(invocation)) {
                    return true;
                }
                receiver = receiver(invocation);
            } else if (receiver instanceof MemberSelectTree select) {
                receiver = select.getExpression();
            } else {
                return false;
            }
        }
        return false;
    }

    private static boolean cacheCanBeEnabled(MethodInvocationTree invocation) {
        if (invocation.getArguments().isEmpty()) {
            return false;
        }
        ExpressionTree first = stripParens(invocation.getArguments().getFirst());
        return !(first instanceof LiteralTree lit && Boolean.FALSE.equals(lit.getValue()));
    }

    private static ExpressionTree receiver(MethodInvocationTree tree) {
        ExpressionTree select = tree.getMethodSelect();
        return select instanceof MemberSelectTree memberSelect ? memberSelect.getExpression() : null;
    }

    private static ExpressionTree stripParens(ExpressionTree expr) {
        while (expr instanceof ParenthesizedTree paren) {
            expr = paren.getExpression();
        }
        return expr;
    }

    private static String methodName(MethodInvocationTree tree) {
        ExpressionTree sel = tree.getMethodSelect();
        if (sel instanceof MemberSelectTree mst) return mst.getIdentifier().toString();
        return sel.toString();
    }

    private static String buildMessage(TriggerKind kind) {
        String specific = switch (kind) {
            case STATUS_CODE ->
                "getResponseCode() is called in a broad or 5xx condition but the branch returns " +
                "instead of throwing";
            case NULL_DESERIALIZE ->
                "getResponseJsonObject/List/Map() is null-checked in the condition but the null " +
                "branch returns instead of throwing";
            default -> "response validation branch returns instead of throwing";
        };
        return "goThen() " + specific + ". " +
               "Returning instead of throwing on a failed cached request can store a value you " +
               "do not want cached, causing wrong behavior that is difficult to debug and fix. " +
               "Throw a JurlException so the attempt is treated as failed and the fallback value " +
               "is not written to JurlCache.";
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
                return null;
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
            AtomicBoolean hasStatusCodeFailureCheck = new AtomicBoolean(false);
            AtomicBoolean hasDeserializeNullCheck = new AtomicBoolean(false);
            boolean boundedFourHundredStatusCheck = isBoundedFourHundredStatusCheck(condition);

            new TreeScanner<Void, Void>() {
                @Override
                public Void visitBinary(BinaryTree node, Void unused) {
                    ExpressionTree left = node.getLeftOperand();
                    ExpressionTree right = node.getRightOperand();
                    Tree.Kind op = node.getKind();

                    // STATUS_CODE: getResponseCode() compared against a numeric literal,
                    // where the comparison is true for error/failure codes (not the success path).
                    // e.g. code >= 400, code > 299, code != 200 — all failure checks.
                    // e.g. code == 200, code < 400, code <= 299 — success checks, not flagged.
                    if (!boundedFourHundredStatusCheck && callsGetResponseCode(left)) {
                        Integer constant = intConstant(right);
                        if (constant != null && isFailureComparison(op, constant)) {
                            hasStatusCodeFailureCheck.set(true);
                        }
                    } else if (!boundedFourHundredStatusCheck && callsGetResponseCode(right)) {
                        Integer constant = intConstant(left);
                        if (constant != null && isFailureComparison(flip(op), constant)) {
                            hasStatusCodeFailureCheck.set(true);
                        }
                    }

                    // NULL_DESERIALIZE: only `expr == null` or `null == expr` — the failure path.
                    // `!= null` guards the success path; the else-branch may throw correctly.
                    if (op == Tree.Kind.EQUAL_TO) {
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

            if (hasStatusCodeFailureCheck.get()) return TriggerKind.STATUS_CODE;
            if (hasDeserializeNullCheck.get()) return TriggerKind.NULL_DESERIALIZE;
            return TriggerKind.NONE;
        }

        /**
         * Returns true when the comparison operator applied to getResponseCode() vs {@code constant}
         * selects the failure path — i.e., the condition is true for error/non-success codes.
         *
         * <p>Treats 200-299 as the success range. Any comparison that is true only for codes
         * outside that range on the then-branch is a failure check.
         */
        private boolean isFailureComparison(Tree.Kind op, int constant) {
            // 3xx redirects are excluded: when followRedirects(false) is set, a 3xx inside
            // goThen() is legitimate data (e.g. reading the Location header). Explicit 4xx
            // no-data paths are cacheable; broad predicates that include 5xx still warn.
            return switch (op) {
                // code >= 400  →  true for 4xx/5xx  →  failure
                case GREATER_THAN_EQUAL -> constant >= 400;
                // code > 399   →  equivalent to >= 400
                case GREATER_THAN -> constant >= 399;
                // code != 200, code != 201  →  true for everything except that code  →  failure
                // (only flag when the excluded value is in the 2xx range)
                case NOT_EQUAL_TO -> constant >= 200 && constant <= 299;
                // code == 400/404 is usually deterministic no-data; exact 5xx remains retryable.
                case EQUAL_TO -> constant >= 500;
                // success checks (== 200, < 400, <= 299, etc.) — not flagged
                default -> false;
            };
        }

        private boolean isBoundedFourHundredStatusCheck(ExpressionTree condition) {
            StatusBounds bounds = new StatusBounds();
            collectStatusBounds(condition, bounds);
            return bounds.lower != null && bounds.lower >= 400
                && bounds.upper != null && bounds.upper <= 499;
        }

        private void collectStatusBounds(ExpressionTree expr, StatusBounds bounds) {
            expr = stripParentheses(expr);
            if (!(expr instanceof BinaryTree node)) {
                return;
            }
            if (node.getKind() == Tree.Kind.CONDITIONAL_AND) {
                collectStatusBounds(node.getLeftOperand(), bounds);
                collectStatusBounds(node.getRightOperand(), bounds);
                return;
            }

            ExpressionTree left = node.getLeftOperand();
            ExpressionTree right = node.getRightOperand();
            Tree.Kind op = node.getKind();
            Integer constant = null;
            if (callsGetResponseCode(left)) {
                constant = intConstant(right);
            } else if (callsGetResponseCode(right)) {
                constant = intConstant(left);
                op = flip(op);
            }
            if (constant == null) {
                return;
            }
            switch (op) {
                case GREATER_THAN_EQUAL -> bounds.lower = max(bounds.lower, constant);
                case GREATER_THAN -> bounds.lower = max(bounds.lower, constant + 1);
                case LESS_THAN_EQUAL -> bounds.upper = min(bounds.upper, constant);
                case LESS_THAN -> bounds.upper = min(bounds.upper, constant - 1);
                default -> {}
            }
        }

        private ExpressionTree stripParentheses(ExpressionTree expr) {
            while (expr instanceof ParenthesizedTree paren) {
                expr = paren.getExpression();
            }
            return expr;
        }

        private Integer max(Integer current, int next) {
            return current == null ? next : Math.max(current, next);
        }

        private Integer min(Integer current, int next) {
            return current == null ? next : Math.min(current, next);
        }

        private static class StatusBounds {
            Integer lower;
            Integer upper;
        }

        /** Flips a comparison operator for when the operands are reversed (constant op code). */
        private Tree.Kind flip(Tree.Kind op) {
            return switch (op) {
                case GREATER_THAN -> Tree.Kind.LESS_THAN;
                case GREATER_THAN_EQUAL -> Tree.Kind.LESS_THAN_EQUAL;
                case LESS_THAN -> Tree.Kind.GREATER_THAN;
                case LESS_THAN_EQUAL -> Tree.Kind.GREATER_THAN_EQUAL;
                default -> op; // EQUAL_TO, NOT_EQUAL_TO are symmetric
            };
        }

        private boolean callsGetResponseCode(ExpressionTree expr) {
            return expr instanceof MethodInvocationTree mit
                && "getResponseCode".equals(methodName(mit));
        }

        private Integer intConstant(ExpressionTree expr) {
            if (expr instanceof LiteralTree lit && lit.getValue() instanceof Integer i) {
                return i;
            }
            return null;
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

    }
}
