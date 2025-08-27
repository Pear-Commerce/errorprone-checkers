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
import com.sun.source.tree.MethodInvocationTree;
import com.sun.source.tree.ParenthesizedTree;
import com.sun.source.tree.TypeCastTree;

import javax.lang.model.element.Element;
import java.util.Set;

@AutoService(BugChecker.class)
@BugPattern(
    name = "VavrTryGetOrNullWithoutOnFailure",
    summary = "Try.getOrNull() hides exceptions; call onFailure(...) or use get()/getOrElseThrow(...).",
    severity = SeverityLevel.WARNING
)
public final class VavrTryGetOrNullWithoutOnFailure extends BugChecker
    implements BugChecker.MethodInvocationTreeMatcher {

    private static final String TRY_CLASS = "io.vavr.control.Try";

    // What we consider “handled/safe” earlier in the chain
    private static final Set<String> HANDLERS_OR_SAFE = Set.of(
        "onFailure", "orElseRun", "recover", "recoverWith", "fold",
        "get", "getOrElseThrow", "failed" // safe terminals
    );

    private static final Matcher<ExpressionTree> GET_OR_NULL =
        instanceMethod().onDescendantOf(TRY_CLASS).named("getOrNull");

    @Override
    public Description matchMethodInvocation(MethodInvocationTree tree, VisitorState state) {
        if (!GET_OR_NULL.matches(tree, state)) return Description.NO_MATCH;

        // If the fluent chain already handled failure, don't flag.
        if (chainAlreadyHandlesFailure(ASTHelpers.getReceiver(tree), state)) {
            return Description.NO_MATCH;
        }

        return buildDescription(tree)
            .setMessage("Calling Try.getOrNull() without onFailure(...) hides exceptions. " +
                        "Prefer get() / getOrElseThrow(...) or handle via onFailure/orElseRun/recover/fold.")
            .build();
    }

    /** Walk left through the fluent chain looking for handlers/safe terminals. */
    private static boolean chainAlreadyHandlesFailure(ExpressionTree recv, VisitorState state) {
        ExpressionTree cur = unwrap(recv);
        while (cur instanceof MethodInvocationTree) {
            MethodInvocationTree m = (MethodInvocationTree) cur;
            Element sym = ASTHelpers.getSymbol(m);
            if (sym != null) {
                String name = sym.getSimpleName().toString();
                if (HANDLERS_OR_SAFE.contains(name)) return true;
                // Special-case: toEither() without args preserves Throwable → treat as safe
                if (name.equals("toEither") && m.getArguments().isEmpty()) return true;
            }
            cur = unwrap(ASTHelpers.getReceiver(m));
        }
        return false;
    }

    /** Strip parens/casts so we don't miss handlers due to syntax noise. */
    private static ExpressionTree unwrap(ExpressionTree e) {
        ExpressionTree cur = e;
        boolean changed;
        do {
            changed = false;
            if (cur instanceof ParenthesizedTree) {
                cur = ((ParenthesizedTree) cur).getExpression();
                changed = true;
            } else if (cur instanceof TypeCastTree) {
                cur = ((TypeCastTree) cur).getExpression();
                changed = true;
            }
        } while (changed);
        return cur;
    }
}
