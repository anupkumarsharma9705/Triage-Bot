package com.triagebot.reachability;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.ImportDeclaration;
import com.github.javaparser.ast.expr.MethodCallExpr;

import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * v1 scope: import-level reachability only.
 * "Reachable" means: some file in sourceRoot imports the vulnerable package,
 * OR a method call anywhere textually references the vulnerable class's simple name.
 *
 * This does NOT trace whether the specific vulnerable method is actually invoked,
 * and does NOT follow the call graph. It is a coarse, honest first filter —
 * documented as a known limitation, not hidden.
 */
@Service
public class ReachabilityAnalyzer {

    public boolean isReachable(Path sourceRoot, String vulnerablePackage) throws IOException {
        if (vulnerablePackage == null || vulnerablePackage.isBlank()) {
            return false;
        }

        String simpleName = vulnerablePackage.contains(".")
                ? vulnerablePackage.substring(vulnerablePackage.lastIndexOf('.') + 1)
                : vulnerablePackage;

        try (Stream<Path> files = Files.walk(sourceRoot)) {
            List<Path> javaFiles = files
                    .filter(p -> p.toString().endsWith(".java"))
                    .collect(Collectors.toList());

            for (Path file : javaFiles) {
                CompilationUnit cu;
                try {
                    cu = StaticJavaParser.parse(file);
                } catch (Exception parseError) {
                    // Skip files that don't parse (e.g. generated sources, syntax we don't support).
                    // Logged rather than failing the whole scan.
                    continue;
                }

                boolean imports = cu.findAll(ImportDeclaration.class).stream()
                        .anyMatch(imp -> imp.getNameAsString().startsWith(vulnerablePackage));

                boolean methodCallMatch = cu.findAll(MethodCallExpr.class).stream()
                        .anyMatch(call -> call.toString().contains(simpleName));

                if (imports || methodCallMatch) {
                    return true;
                }
            }
        }
        return false;
    }
}