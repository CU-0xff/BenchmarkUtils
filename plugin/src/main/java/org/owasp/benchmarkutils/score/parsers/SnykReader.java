/**
 * OWASP Benchmark Project
 *
 * <p>This file is part of the Open Web Application Security Project (OWASP) Benchmark Project For
 * details, please see <a
 * href="https://owasp.org/www-project-benchmark/">https://owasp.org/www-project-benchmark/</a>.
 *
 * <p>The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, version 2.
 *
 * <p>The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details.
 *
 * @author Frank Fischer
 * @created 2023
 */
package org.owasp.benchmarkutils.score.parsers;

import java.util.HashMap;
import org.json.JSONArray;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

// Result file should be named Benchmark_1.2-SnykCode-v1.0.0-[time to scan in seconds].json

public class SnykReader extends Reader {

    private static final String SNYKCWEPREFIX = "CWE-";
    private final int SNYKCWEPREFIXLENGTH = SNYKCWEPREFIX.length();

    @Override
    public boolean canRead(ResultFile resultFile) {
        try {
            boolean result =
                    resultFile.filename().endsWith(".json")
                            && resultFile.isJson()
                            && (resultFile // identify Snyk Code engine
                                    .json()
                                    .getJSONArray("runs")
                                    .getJSONObject(0)
                                    .getJSONObject("tool")
                                    .getJSONObject("driver")
                                    .getString("name")
                                    .equals("SnykCode"));
            return result;
        } catch (Exception e) {
            System.out.println("Exception during discovery");
            return false;
        }
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        /*
         * This parser was written against the sarif-schema as used by Snyk in Feb/2023
         */

        // Path to CWEs in Snyk SARIF:
        // runs[]0{}tool{}driver{}rules[]0{}properties{}cwe[]0{}="CWE-23"

        JSONArray runs = resultFile.json().getJSONArray("runs");

        TestSuiteResults tr =
                new TestSuiteResults("SnykCode", true, TestSuiteResults.ToolType.SAST);
        // Scan time is not included in the sarif-schema and have to be supplied alternatively

        tr.setTime(resultFile.file()); // This grabs the scan time out of the filename, if provided
        // e.g., Benchmark_1.2-SnykCode-v1.0.0-[time to scan in seconds].json

        for (int i = 0; i < runs.length(); i++) {
            // There are 1 or more runs in each results file, one per language found (Java,
            // JavaScript, etc.)
            JSONObject run = runs.getJSONObject(i);

            // First, set the version of LGTM used to do the scan
            JSONObject driver = run.getJSONObject("tool").getJSONObject("driver");
            tr.setToolVersion(driver.getString("semanticVersion"));

            // In Snyk's SARIF all CWEs are encoded in the rules section
            // Then, identify all the rules that report results and which CWEs they map to
            JSONArray rules = driver.getJSONArray("rules");
            // System.out.println("Found: " + rules.length() + " rules.");
            HashMap<String, Integer> rulesUsed = parseSnykRules(rules);
            // System.out.println("Parsed: " + rulesUsed.size() + " rules.");

            // Finally, parse out all the results
            JSONArray results = run.getJSONArray("results");
            // System.out.println("Found: " + results.length() + " results.");

            for (int j = 0; j < results.length(); j++) {
                TestCaseResult tcr =
                        parseSnykFinding(results.getJSONObject(j), rulesUsed); // , version );
                if (tcr != null) {
                    tr.put(tcr);
                }
            }
        }

        return tr;
    }

    private HashMap<String, Integer> parseSnykRules(JSONArray rulesJSON) {
        HashMap<String, Integer> rulesUsed = new HashMap<String, Integer>();

        for (int j = 0; j < rulesJSON.length(); j++) {
            JSONObject ruleJSON = rulesJSON.getJSONObject(j);

            try {

                String ruleId = ruleJSON.getString("id");
                JSONArray cwes = ruleJSON.getJSONObject("properties").getJSONArray("cwe");
                for (int i = 0; i < cwes.length(); i++) {
                    String val = cwes.getString(i);
                    if (val.startsWith(SNYKCWEPREFIX)) {
                        // NOTE: If you try to map the rules here, you have to map EVERY rule in the
                        // current ruleset, even though many of those rules won't have results. So
                        // instead we map them later when there is actually a finding by that rule.
                        rulesUsed.put(ruleId, Integer.parseInt(val.substring(SNYKCWEPREFIXLENGTH)));
                        System.out.println(
                                "Found: " + ruleId + " " + val.substring(SNYKCWEPREFIXLENGTH));
                    }
                }

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return rulesUsed;
    }

    private TestCaseResult parseSnykFinding(
            JSONObject finding, HashMap<String, Integer> rulesUsed) {
        try {
            String filename = null;
            JSONArray locations = finding.getJSONArray("locations");
            filename =
                    locations
                            .getJSONObject(0)
                            .getJSONObject("physicalLocation")
                            .getJSONObject("artifactLocation")
                            .getString("uri");
            filename = filename.substring(filename.lastIndexOf('/') + 1);
            if (filename.startsWith(BenchmarkScore.TESTCASENAME)) {
                TestCaseResult tcr = new TestCaseResult();
                String testNumber =
                        filename.substring(
                                BenchmarkScore.TESTCASENAME.length() + 1,
                                filename.lastIndexOf('.'));
                tcr.setNumber(Integer.parseInt(testNumber));
                String ruleId = finding.getString("ruleId");
                Integer cweForRule = rulesUsed.get(ruleId);
                /* System.out.println(
                "Found finding in: "
                        + testNumber
                        + " of type: "
                        + ruleId
                        + " CWE: "
                        + cweForRule); */
                if (cweForRule == null) {
                    // All rules should have an CWE bound, otherwise send error message
                    System.out.println(
                            "WARNING: finding found for ruleId: "
                                    + ruleId
                                    + " with no CWE mapping");

                    return null;
                }

                if (locations.length() > 1) {
                    System.out.println(
                            "WARNING: Unexpectedly found more than one location for finding against rule: "
                                    + ruleId);
                }
                int cwe = mapCWE(ruleId, cweForRule);
                tcr.setCWE(cwe);
                tcr.setEvidence(finding.getJSONObject("message").getString("text"));
                return tcr;
            } // end if
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private int mapCWE(String ruleName, Integer cweNumber) {

        switch (cweNumber) {
                // These are properly mapped by default
            case 22: // java/path-injection and zipslip
            case 78: // java & js/command-line-injection
            case 79: // java/xss & js/reflected-xss
            case 89: // java & js/sql-injection and similar sqli rules
            case 90: // java/ldap-injection
            case 327: // java/weak-cryptographic-algorithm
            case 611: // java & js/xxe
            case 614: // java/insecure-cookie
            case 643: // java/xml/xpath-injection
            case 330: // java/insecuresecret
            case 501: // java/TrustBoundaryViolation
            case 916: // java/Insecurehash
            case 1004: // java/WebCookieMissesCallToSetHttpOnly
                return cweNumber.intValue(); // Return CWE as is
            case 23: // java/PT - child of CWE 22
                return 22;
                // These rules we care about, but have to map to the CWE we expect
            case 335: // java/predictable-seed - This mapping improves the tool's score
                return 330; // Weak Random

            case 113: // java/http-response-splitting
            case 117: // js/log-injection
            case 134: // java/tainted-format-string
            case 209: // java/stack-trace-exposure
            case 404: // java/database-resource-leak
            case 477: // java/deprecated-call
            case 485: // java/abstract-to-concrete-cast
            case 561: // java/unused-parameter
            case 563: // js/useless-assignment-to-local
            case 570: // java/constant-comparison
            case 685: // java/unused-format-argument
            case 730: // js/regex-injection (i.e., DOS)
            case 776: // js/xml-bomb (i.e., XEE, as opposed to XXE, which is already mapped above
            case 843: // js/type-confusion-through-parameter-tampering
                return cweNumber.intValue(); // Return CWE as is
            default:
                System.out.println(
                        "SnykCode parser encountered new unmapped vulnerability type: "
                                + cweNumber
                                + " for rule: "
                                + ruleName);
        }
        return 0; // Not mapped to anything
    }
}
