package com.pearcommerce.errorprone.vavr;

import static com.google.errorprone.matchers.Matchers.instanceMethod;

import com.google.auto.service.AutoService;
import com.google.errorprone.BugPattern;
import com.google.errorprone.BugPattern.SeverityLevel;
import com.google.errorprone.VisitorState;
import com.google.errorprone.bugpatterns.BugChecker;
import com.google.errorprone.matchers.Description;
import com.google.errorprone.matchers.Matcher;
import com.google.errorprone.util.ASTHelpers;
import com.sun.source.tree.ExpressionTree;
import com.sun.source.tree.MemberSelectTree;
import com.sun.source.tree.MethodInvocationTree;
import com.sun.source.tree.ParenthesizedTree;
import com.sun.source.tree.TypeCastTree;

import javax.lang.model.element.Element;
import java.util.Set;
@AutoService(BugChecker.class)
@BugPattern(
    name = "VavrTryGetOrNullWithoutOnFailure",
    summary = "Try.getOrNull() hides exceptions; call onFailure(...) or use get()/getOrElseThrow(...).",
    severity = SeverityLevel.ERROR,
    link = "https://chatgpt.com/share/68b06dc9-13ac-8007-8209-9abcd20f523e"
)
public final class VavrTryGetOrNullWithoutOnFailure extends BugChecker
    implements BugChecker.MethodInvocationTreeMatcher {

    private static final String TRY_CLASS = "io.vavr.control.Try";

    // Anything that clearly observes/handles the failure or ends safely.
    private static final Set<String> HANDLERS_OR_SAFE = Set.of(
        "onFailure", "orElseRun", "recover", "recoverWith", "fold",
        "get", "getOrElseThrow", "failed"
    );

    private static final Matcher<ExpressionTree> GET_OR_NULL =
        instanceMethod().onDescendantOf(TRY_CLASS).named("getOrNull");

    @Override
    public Description matchMethodInvocation(MethodInvocationTree tree, VisitorState state) {
        if (!GET_OR_NULL.matches(tree, state)) return Description.NO_MATCH;

        if (chainAlreadyHandlesFailure(ASTHelpers.getReceiver(tree), state)) {
            return Description.NO_MATCH;
        }

        return buildDescription(tree)
            .setMessage("Calling Try.getOrNull() without onFailure(...) hides exceptions. " +
                        "Prefer get()/getOrElseThrow() or handle via onFailure/orElseRun/recover/fold.")
            .build();
    }

    /** Walk left through the fluent chain and look for a handler/safe terminal. */
    private static boolean chainAlreadyHandlesFailure(ExpressionTree recv, VisitorState state) {
        ExpressionTree cur = unwrap(recv);
        while (cur instanceof MethodInvocationTree) {
            MethodInvocationTree m = (MethodInvocationTree) cur;
            String name = methodName(m);
            if (HANDLERS_OR_SAFE.contains(name)) return true;
            // zero-arg toEither() preserves Throwable → treat as safe
            if (name.equals("toEither") && m.getArguments().isEmpty()) return true;
            cur = unwrap(ASTHelpers.getReceiver(m));
        }
        return false;
    }

    private static String methodName(MethodInvocationTree m) {
        Element sym = ASTHelpers.getSymbol(m);
        if (sym != null) return sym.getSimpleName().toString();
        // Fallback when symbol can’t be resolved (lambdas, inference, etc.)
        if (m.getMethodSelect() instanceof MemberSelectTree sel) {
            return sel.getIdentifier().toString();
        }
        // Last resort: strip any qualifier
        String s = m.getMethodSelect().toString();
        int dot = s.lastIndexOf('.');
        return dot >= 0 ? s.substring(dot + 1) : s;
    }

    /** Strip parens/casts that can appear in chains so we don’t miss handlers. */
    private static ExpressionTree unwrap(ExpressionTree e) {
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
