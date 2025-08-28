package com.pearcommerce.errorprone.async;

import com.google.auto.service.AutoService;
import com.google.errorprone.BugPattern;
import com.google.errorprone.BugPattern.SeverityLevel;
import com.google.errorprone.VisitorState;
import com.google.errorprone.bugpatterns.BugChecker;
import com.google.errorprone.fixes.SuggestedFix;
import com.google.errorprone.fixes.SuggestedFixes;
import com.google.errorprone.matchers.Description;
import com.google.errorprone.matchers.Matcher;
import com.sun.source.tree.ExpressionTree;
import com.sun.source.tree.MethodInvocationTree;

import static com.google.errorprone.matchers.Matchers.staticMethod;

@AutoService(BugChecker.class)
@BugPattern(
    name = "CompletableFutureMissingExecutor",
    summary = "Specify an Executor when using CompletableFuture.runAsync/supplyAsync.",
    explanation =
        "The 1-arg overloads of CompletableFuture.runAsync and supplyAsync use the global common ForkJoin pool, "
        + "which competes with other workloads globally. This can cause inconsistent behavior or even deadlock.",
    severity = SeverityLevel.ERROR
)
public class CompletableFutureMissingExecutor extends BugChecker
    implements BugChecker.MethodInvocationTreeMatcher {

    private static final String CF = "java.util.concurrent.CompletableFuture";

    private static final Matcher<ExpressionTree> SUPPLY_ASYNC_ONE_ARG =
        staticMethod().onClass(CF).named("supplyAsync")
            .withParameters("java.util.function.Supplier");

    private static final Matcher<ExpressionTree> RUN_ASYNC_ONE_ARG =
        staticMethod().onClass(CF).named("runAsync")
            .withParameters("java.lang.Runnable");

    @Override
    public Description matchMethodInvocation(MethodInvocationTree tree, VisitorState state) {
        if (!(SUPPLY_ASYNC_ONE_ARG.matches(tree, state) || RUN_ASYNC_ONE_ARG.matches(tree, state))) {
            return Description.NO_MATCH;
        }

        SuggestedFix.Builder fix = SuggestedFix.builder()
            .addImport("com.pear.availabilities.Pools");

        if (!tree.getArguments().isEmpty()) {
            ExpressionTree lastArg = tree.getArguments().get(tree.getArguments().size() - 1);
            fix.postfixWith(lastArg, ", pools.getYourMoreIsolatedPool()");
        }

        // Append after the last existing argument
        if (!tree.getArguments().isEmpty()) {
            ExpressionTree lastArg = tree.getArguments().get(tree.getArguments().size() - 1);
            fix.postfixWith(lastArg, ", pools.getYourMoreIsolatedPool()");
        }

        return buildDescription(tree)
            .setMessage("Use the 2-arg overload with an explicit Executor.")
            .addFix(fix.build())
            .build();
    }
}
