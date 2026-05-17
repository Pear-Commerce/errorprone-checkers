package com.pearcommerce.errorprone.stringtemplates;

import com.google.auto.service.AutoService;
import com.google.errorprone.BugPattern;
import com.google.errorprone.BugPattern.SeverityLevel;
import com.google.errorprone.VisitorState;
import com.google.errorprone.bugpatterns.BugChecker;
import com.google.errorprone.matchers.Description;
import com.sun.source.tree.CompilationUnitTree;

@AutoService(BugChecker.class)
@BugPattern(
    name = "NoJavaStringTemplates",
    summary = "Use Manifold string interpolation instead of Java preview string templates.",
    explanation =
        "Java string templates were a Java 21/22 preview feature and are not available in newer LTS releases. "
            + "Use Manifold ${...} interpolation, or ordinary Java formatting / "
            + "@DisableStringLiteralTemplates for files with literal ${...} placeholders.",
    severity = SeverityLevel.ERROR,
    linkType = BugPattern.LinkType.CUSTOM,
    link = "https://docs.oracle.com/en/java/javase/23/migrate/"
)
public final class NoJavaStringTemplates extends BugChecker
    implements BugChecker.CompilationUnitTreeMatcher {

    @Override
    public Description matchCompilationUnit(CompilationUnitTree tree, VisitorState state) {
        CharSequence source = state.getSourceCode();
        if (source == null || !hasJavaStringTemplate(source)) {
            return Description.NO_MATCH;
        }

        return buildDescription(tree)
            .setMessage(
                "Java string templates are blocked because they prevent upgrading to a current LTS JDK. "
                    + "Use Manifold ${...} interpolation, or ordinary Java formatting / "
                    + "@DisableStringLiteralTemplates for files that need literal ${...} placeholders."
            )
            .build();
    }

    static boolean hasJavaStringTemplate(CharSequence source) {
        for (int i = 0; i < source.length(); i++) {
            char c = source.charAt(i);
            if (c == '"' || c == '\'') {
                i = skipQuoted(source, i);
                continue;
            }
            if (c == '/' && i + 1 < source.length()) {
                char next = source.charAt(i + 1);
                if (next == '/') {
                    i = skipLineComment(source, i + 2);
                    continue;
                }
                if (next == '*') {
                    i = skipBlockComment(source, i + 2);
                    continue;
                }
            }
            if (isStringTemplateDelimiter(source, i)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isStringTemplateDelimiter(CharSequence source, int i) {
        if (source.charAt(i) != '.') {
            return false;
        }
        int cursor = skipWhitespace(source, i + 1);
        return cursor < source.length() && source.charAt(cursor) == '"';
    }

    private static int skipWhitespace(CharSequence source, int i) {
        while (i < source.length() && Character.isWhitespace(source.charAt(i))) {
            i++;
        }
        return i;
    }

    private static int skipQuoted(CharSequence source, int i) {
        char quote = source.charAt(i);
        if (quote == '"' && i + 2 < source.length()
            && source.charAt(i + 1) == '"' && source.charAt(i + 2) == '"') {
            return skipTextBlock(source, i + 3);
        }
        boolean escaped = false;
        for (int cursor = i + 1; cursor < source.length(); cursor++) {
            char c = source.charAt(cursor);
            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == quote) {
                return cursor;
            }
        }
        return source.length() - 1;
    }

    private static int skipTextBlock(CharSequence source, int i) {
        for (int cursor = i; cursor + 2 < source.length(); cursor++) {
            if (source.charAt(cursor) == '"'
                && source.charAt(cursor + 1) == '"'
                && source.charAt(cursor + 2) == '"') {
                return cursor + 2;
            }
        }
        return source.length() - 1;
    }

    private static int skipLineComment(CharSequence source, int i) {
        for (int cursor = i; cursor < source.length(); cursor++) {
            if (source.charAt(cursor) == '\n') {
                return cursor;
            }
        }
        return source.length() - 1;
    }

    private static int skipBlockComment(CharSequence source, int i) {
        for (int cursor = i; cursor + 1 < source.length(); cursor++) {
            if (source.charAt(cursor) == '*' && source.charAt(cursor + 1) == '/') {
                return cursor + 1;
            }
        }
        return source.length() - 1;
    }
}
