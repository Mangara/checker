/*
 * Copyright 2014 Sander Verdonschot <sander.verdonschot at gmail.com>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package checker;

public abstract class Test {

    private String name;

    public Test(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public abstract TestResult run(int timePerTest, Checker checker);

    public static void myAssert(boolean b) throws CorrectnessException {
        myAssert(b, null);
    }

    public static void myAssert(boolean b, String message) throws CorrectnessException {
        if (!b) {
            throw new CorrectnessException(message);
        }
    }

    protected TestResult addScores(TestResult... results) {
        TestResult result = new TestResult(0, 0, null, null);

        for (TestResult r : results) {
            result.score += r.score;
            result.maxScore += r.maxScore;

            if (r.comment != null) {
                result.comment = (result.comment == null ? r.comment : result.comment + String.format("%n") + r.comment);
            }

            if (r.details != null) {
                result.details = (result.details == null ? r.details : result.details + String.format("%n") + r.details);
            }
        }

        return result;
    }

    protected TestResult subtractScores(int totalMax, TestResult... results) {
        TestResult result = new TestResult(totalMax, totalMax, null, null);

        for (TestResult r : results) {
            result.score -= r.score;

            if (result.comment == null) {
                result.comment = r.comment;
            } else if (r.comment != null) {
                result.comment += String.format("%n") + r.comment;
            }

            if (result.details == null) {
                result.details = r.details;
            } else if (r.details != null) {
                result.details += String.format("%n") + r.details;
            }
        }

        return result;
    }
}
