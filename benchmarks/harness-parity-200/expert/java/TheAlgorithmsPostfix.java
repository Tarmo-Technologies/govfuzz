// SPDX-License-Identifier: Apache-2.0

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.thealgorithms.stacks.PostfixEvaluator;

public final class TheAlgorithmsPostfix {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        PostfixEvaluator.evaluatePostfix(data.consumeRemainingAsString());
    }
}
