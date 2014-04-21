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

public class TestResult {

    public int score;
    public int maxScore;
    public String comment; // Printed to both stdout and stderr
    public String details; // Only printed to stderr

    public TestResult(int score, int maxScore, String comment, String details) {
        this.score = score;
        this.maxScore = maxScore;
        this.comment = comment;
        this.details = details;
    }

    public TestResult(int score, int maxScore, String comment) {
        this(score, maxScore, comment, null);
    }
}
