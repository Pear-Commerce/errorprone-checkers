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

@AutoService(BugChecker.class)
@BugPattern(
    name = "VavrTryGetOrNullWithoutOnFailure",
    summary = "Try.getOrNull() hides exceptions; call onFailure(...) or use get()/getOrElseThrow(...).",
    severity = SeverityLevel.WARNING
)
public final class VavrTryGetOrNullWithoutOnFailure extends BugChecker
    implements BugChecker.MethodInvocationTreeMatcher {

  private static final String TRY_CLASS = "io.vavr.control.Try";

  private static final Matcher<ExpressionTree> GET_OR_NULL =
      instanceMethod().onExactClass(TRY_CLASS).named("getOrNull");

  @Override
  public Description matchMethodInvocation(MethodInvocationTree tree, VisitorState state) {
    if (!GET_OR_NULL.matches(tree, state)) return Description.NO_MATCH;

    // If an earlier link in the fluent chain is onFailure(...), allow it.
    ExpressionTree recv = ASTHelpers.getReceiver(tree);
    while (recv instanceof MethodInvocationTree) {
      MethodInvocationTree m = (MethodInvocationTree) recv;
      if ("onFailure".contentEquals(m.getMethodSelect().toString().replaceAll("^.*\\.", ""))) {
        return Description.NO_MATCH;
      }
      recv = ASTHelpers.getReceiver(m);
    }

    return buildDescription(tree)
        .setMessage("Calling Try.getOrNull() without onFailure(...) hides exceptions. " +
            "Prefer get() / getOrElseThrow(...) or handle via onFailure(...).")
        .build();
  }
}
