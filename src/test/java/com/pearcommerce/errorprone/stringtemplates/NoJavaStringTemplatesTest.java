package com.pearcommerce.errorprone.stringtemplates;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class NoJavaStringTemplatesTest {

    @Test
    public void detectsStrStringTemplate() {
        assertTrue(NoJavaStringTemplates.hasJavaStringTemplate(
            "class Test { String s = STR.\"hello \\{name}\"; }"
        ));
    }

    @Test
    public void detectsBuiltInAndCustomTemplateProcessors() {
        assertTrue(NoJavaStringTemplates.hasJavaStringTemplate(
            "class Test { String s = FMT.\"hello %s\\{name}\"; }"
        ));
        assertTrue(NoJavaStringTemplates.hasJavaStringTemplate(
            "class Test { String s = RAW . \"\"\"hello \\{name}\"\"\"; }"
        ));
        assertTrue(NoJavaStringTemplates.hasJavaStringTemplate(
            "class Test { String s = Templates.SQL.\"select \\{id}\"; }"
        ));
    }

    @Test
    public void detectsExpressionTemplateProcessors() {
        assertTrue(NoJavaStringTemplates.hasJavaStringTemplate(
            "class Test { String s = getProcessor().\"hello \\{name}\"; }"
        ));
    }

    @Test
    public void ignoresCommentsAndOrdinaryStrings() {
        assertFalse(NoJavaStringTemplates.hasJavaStringTemplate(
            "// STR.\"hello \\{name}\"\n"
                + "class Test { String s = \"STR.\\\"hello \\\\{name}\\\"\"; }"
        ));
    }
}
